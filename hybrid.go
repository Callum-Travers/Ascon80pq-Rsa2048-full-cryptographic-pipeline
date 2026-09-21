package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/n2vi/ascon/ascon80pq"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// Constants
const (
	KeySize80pq      = 20
	NonceSize        = 16
	rootCertPath     = "root_ca.pem"
	rootKeyPath      = "root_ca_key.pem"
	interCertPath    = "inter_ca.pem"
	interKeyPath     = "inter_ca_key.pem"
	interCRLPath     = "inter_ca.crl"
	interRevokedPath = "inter_revoked.txt"
)

//Helper Functions

func mustRand(n int) []byte { // generates n random bytes
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func writePrivateKeyPEM(path string, priv *rsa.PrivateKey) error { // writes RSA private key to PEM file
	der := x509.MarshalPKCS1PrivateKey(priv)
	blk := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, blk)
}

func writeCertPEM(path string, der []byte) error { // writes certificate to PEM file
	blk := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, blk)
}

func normalizeTextReader(r io.Reader) io.Reader { // normalizes text files to UTF-8, handling BOM if present
	bom := make([]byte, 2)
	n, _ := io.ReadFull(r, bom)
	if n == 2 && bom[0] == 0xFF && bom[1] == 0xFE {
		decoder := unicode.UTF16(unicode.LittleEndian, unicode.ExpectBOM).NewDecoder()
		return transform.NewReader(r, decoder)
	}
	return io.MultiReader(bytes.NewReader(bom[:n]), r)
}

// SHA-256-based SKID/AKID helpers

func buildSKID(pub interface{}) ([]byte, error) { // builds Subject Key Identifier from public key
	pkBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pkBytes)
	return asn1.Marshal(sum[:])
}

func buildAKID(pub interface{}) ([]byte, error) { // builds Authority Key Identifier from public key
	pkBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pkBytes)

	// Correct ASN.1 structure for AKID
	akid := struct {
		KeyIdentifier []byte `asn1:"tag:0,implicit,optional"`
	}{
		KeyIdentifier: sum[:],
	}

	return asn1.Marshal(akid)
}

func newSerial() *big.Int {
	return big.NewInt(time.Now().UnixNano())
}

func timeOp(label string, iters int, fn func() error) {
	var total time.Duration
	var min = time.Duration(1<<63 - 1)
	var max time.Duration

	for i := 0; i < iters; i++ {
		start := time.Now()
		_ = fn()
		d := time.Since(start)

		total += d
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}

	avg := total / time.Duration(iters)
	fmt.Printf("%s: iters=%d avg=%s min=%s max=%s\n", label, iters, avg, min, max)
}

//PKI and CRL config

// creates certificates, ensuring serial numbers are valid
func createCert(template, parent *x509.Certificate, pub *rsa.PublicKey, parentPriv *rsa.PrivateKey) ([]byte, error) {
	if template == nil {
		return nil, fmt.Errorf("createCert: template is nil")
	}
	if parent == nil {
		return nil, fmt.Errorf("createCert: parent is nil")
	}

	// Ensure template has a valid serial
	if template.SerialNumber == nil || template.SerialNumber.Sign() == 0 {
		fmt.Println("DEBUG: fixing template serial (was nil or zero)")
		template.SerialNumber = new(big.Int).SetBytes(mustRand(16))
	}

	// Ensure parent has a valid serial
	if parent.SerialNumber == nil || parent.SerialNumber.Sign() == 0 {
		fmt.Println("DEBUG: fixing parent serial (was nil or zero)")
		parent.SerialNumber = new(big.Int).SetBytes(mustRand(16))
	}

	//fmt.Printf("DEBUG: about to CreateCertificate\n  template CN=%q serial=%s\n  parent   CN=%q serial=%s\n",
	//template.Subject.CommonName,
	//template.SerialNumber.String(),
	//parent.Subject.CommonName,
	//parent.SerialNumber.String(),
	//)

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("DEBUG: panic in CreateCertificate\n  template=%+v\n  parent=%+v\n", template, parent)
			panic(r)
		}
	}()

	return x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
}

func loadRevokedSerials() ([]*big.Int, error) { // loads revoked serials from file
	data, err := os.ReadFile(interRevokedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []*big.Int{}, nil
		}
		return nil, err
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	var serials []*big.Int
	for _, l := range lines {
		l = bytes.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		n := new(big.Int)
		n, ok := n.SetString(string(l), 10)
		if !ok {
			return nil, fmt.Errorf("invalid serial in revoked list: %s", string(l))
		}
		serials = append(serials, n)
	}
	return serials, nil
}

func appendRevokedSerial(serial *big.Int) error {
	f, err := os.OpenFile(interRevokedPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", serial.String())
	return err
}

func generateCRL(interCert *x509.Certificate, interPriv *rsa.PrivateKey) error { // generates a new CRL based on the current revoked serials list
	serials, err := loadRevokedSerials()
	if err != nil {
		return err
	}
	var revoked []pkix.RevokedCertificate
	now := time.Now()
	for _, s := range serials {
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   s,
			RevocationTime: now,
		})
	}

	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm:  interCert.SignatureAlgorithm,
		RevokedCertificates: revoked,
		ThisUpdate:          now,
		NextUpdate:          now.Add(7 * 24 * time.Hour),
		Number:              big.NewInt(1), //
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, interCert, interPriv)
	if err != nil {
		return err
	}

	blk := &pem.Block{Type: "X509 CRL", Bytes: crlBytes}
	f, err := os.Create(interCRLPath)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, blk)
}

func loadCRL() (*x509.RevocationList, error) { // loads the CRL from PEM file
	data, err := os.ReadFile(interCRLPath)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "X509 CRL" {
		return nil, fmt.Errorf("invalid CRL PEM")
	}
	return x509.ParseRevocationList(blk.Bytes)
}

func isCertRevoked(cert *x509.Certificate, crl *x509.RevocationList) bool {
	for _, rc := range crl.RevokedCertificates {
		if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 { // checking if cert is revoked by comparing serial numbers
			return true
		}
	}
	return false
}

func revokeCert(cert *x509.Certificate, interCert *x509.Certificate, interPriv *rsa.PrivateKey) error {
	if err := appendRevokedSerial(cert.SerialNumber); err != nil { // append to revoked list the serial of the cert being revoked
		return err
	}
	return generateCRL(interCert, interPriv)
}

// Cert Profiles

type CertProfile struct {
	Name        string
	IsCA        bool
	MaxPathLen  int
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	Validity    time.Duration
}

func RootCAProfile() CertProfile { // structure behind the Root CA profiles
	return CertProfile{
		Name:       "root-ca",
		IsCA:       true,
		MaxPathLen: 1,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		Validity:   10 * 365 * 24 * time.Hour,
	}
}

func IntermediateCAProfile() CertProfile { // structure behind the Intermediate CA profiles
	return CertProfile{
		Name:       "intermediate-ca",
		IsCA:       true,
		MaxPathLen: 0,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		Validity:   5 * 365 * 24 * time.Hour,
	}
}

func ClientProfile() CertProfile { // structure behind the Client profiles
	return CertProfile{
		Name:     "client",
		IsCA:     false,
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		Validity: 365 * 24 * time.Hour,
	}
}

func BuildCertTemplateFromProfile(profile CertProfile, cn string, serial *big.Int) *x509.Certificate {
	if serial == nil || serial.Sign() == 0 {
		serial = new(big.Int).SetBytes(mustRand(16))
	}

	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},

		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(profile.Validity),

		KeyUsage:              profile.KeyUsage,
		ExtKeyUsage:           profile.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  profile.IsCA,
		MaxPathLen:            profile.MaxPathLen,

		SignatureAlgorithm: x509.SHA256WithRSA,
	}
}

// PKI construction

func buildT2PKI() (rootCert, interCert *x509.Certificate,
	rootPriv, interPriv *rsa.PrivateKey, err error) {

	// Root CA
	rootPriv, rootPub := RSAKeyGen()
	rootProfile := RootCAProfile()
	rootTemplate := BuildCertTemplateFromProfile(rootProfile, "Root CA", big.NewInt(1))

	rootSKID, err := buildSKID(rootPub)
	if err != nil {
		return
	}
	rootAKID, err := buildAKID(rootPub)
	if err != nil {
		return
	}
	rootTemplate.SubjectKeyId = rootSKID
	rootTemplate.ExtraExtensions = append(rootTemplate.ExtraExtensions,
		pkix.Extension{
			Id:    []int{2, 5, 29, 14}, // Subject Key Identifier
			Value: rootSKID,
		},
		pkix.Extension{
			Id:    []int{2, 5, 29, 35}, // Authority Key Identifier
			Value: rootAKID,
		},
	)

	rootDER, err := createCert(rootTemplate, rootTemplate, rootPub, rootPriv)
	if err != nil {
		return
	}
	if err = writeCertPEM(rootCertPath, rootDER); err != nil {
		return
	}
	if err = writePrivateKeyPEM(rootKeyPath, rootPriv); err != nil {
		return
	}
	rootCert, err = x509.ParseCertificate(rootDER)
	if err != nil {
		return
	}

	// Intermediate CA
	interPriv, interPub := RSAKeyGen()
	interProfile := IntermediateCAProfile()
	interTemplate := BuildCertTemplateFromProfile(interProfile, "Intermediate CA", big.NewInt(2))

	interSKID, err := buildSKID(interPub)
	if err != nil {
		return
	}
	interAKID, err := buildAKID(rootPub)
	if err != nil {
		return
	}
	interTemplate.SubjectKeyId = interSKID
	interTemplate.ExtraExtensions = append(interTemplate.ExtraExtensions,
		pkix.Extension{
			Id:    []int{2, 5, 29, 14}, // Subject Key Identifier
			Value: interSKID,
		},
		pkix.Extension{
			Id:    []int{2, 5, 29, 35}, // Authority Key Identifier
			Value: interAKID,
		},
	)

	interDER, err := createCert(interTemplate, rootCert, interPub, rootPriv)
	if err != nil {
		return
	}
	if err = writeCertPEM(interCertPath, interDER); err != nil {
		return
	}
	if err = writePrivateKeyPEM(interKeyPath, interPriv); err != nil {
		return
	}
	interCert, err = x509.ParseCertificate(interDER)
	if err != nil {
		return
	}

	// Initial CRL
	if err = generateCRL(interCert, interPriv); err != nil {
		return
	}

	return
}
func verifyLeafWithPKI(leaf, inter, root *x509.Certificate, crl *x509.RevocationList) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	inters.AddCert(inter)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("chain verify failed: %w", err)
	}
	if isCertRevoked(leaf, crl) {
		return fmt.Errorf("leaf certificate is revoked")
	}
	return nil
}

//
//  Client issuing and loading
//

// IssueClientCert generates a new client keypair + certificate and writes them to PEM files.
func IssueClientCert(commonName string, serial int64, interCert *x509.Certificate, interPriv *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	clientPriv, clientPub := RSAKeyGen()

	profile := ClientProfile()
	tmpl := BuildCertTemplateFromProfile(profile, commonName, big.NewInt(serial))

	clientSKID, err := buildSKID(clientPub)
	if err != nil {
		return nil, nil, err
	}
	clientAKID, err := buildAKID(interCert.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	tmpl.SubjectKeyId = clientSKID
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions,
		pkix.Extension{
			Id:    []int{2, 5, 29, 14}, // Subject Key Identifier
			Value: clientSKID,
		},
		pkix.Extension{
			Id:    []int{2, 5, 29, 35}, // Authority Key Identifier
			Value: clientAKID,
		},
	)

	//fmt.Printf("DEBUG: IssueClientCert\n  CN=%q serial=%d\n", commonName, serial)
	//fmt.Printf("DEBUG: tmpl.SerialNumber == nil? %v\n", tmpl.SerialNumber == nil)
	//fmt.Printf("DEBUG: interCert == nil? %v\n", interCert == nil)
	//if interCert != nil {
	//fmt.Printf("DEBUG: interCert.SerialNumber == nil? %v\n", interCert.SerialNumber == nil)
	//}

	der, err := createCert(tmpl, interCert, clientPub, interPriv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	if err := writePrivateKeyPEM(commonName+"_priv.pem", clientPriv); err != nil {
		return nil, nil, err
	}
	if err := writeCertPEM(commonName+"_cert.pem", der); err != nil {
		return nil, nil, err
	}

	pubDer, err := x509.MarshalPKIXPublicKey(clientPub)
	if err == nil {
		f, err := os.Create(commonName + "_pub.pem")
		if err == nil {
			defer f.Close()
			pem.Encode(f, &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubDer,
			})
		}
	}

	return cert, clientPriv, nil
}

func LoadClientKey(path string) (*rsa.PrivateKey, error) { // loads RSA private key from PEM file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	return x509.ParsePKCS1PrivateKey(blk.Bytes)
}

func LoadClientCert(path string) (*x509.Certificate, error) { // loads a client certificate from a PEM file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// ASCON Basics

func encryptAscon80pq(plaintext, ad, key, nonce []byte) ([]byte, error) {
	var ct bytes.Buffer
	ascon80pq.Encrypt(&ct, bytes.NewReader(plaintext), ad, nonce, key)
	return ct.Bytes(), nil
}

func decryptAscon80pq(ciphertext, ad, key []byte) ([]byte, error) {
	var pt bytes.Buffer
	if err := ascon80pq.Decrypt(&pt, bytes.NewReader(ciphertext), ad, key); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	return pt.Bytes(), nil
}

//RSA

func RSAKeyGen() (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return priv, &priv.PublicKey
}

func RSAEncrypt(pub *rsa.PublicKey, key []byte) []byte {
	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
	if err != nil {
		panic(err)
	}
	return enc
}

func RSADecrypt(priv *rsa.PrivateKey, enc []byte) []byte {
	dec, err := priv.Decrypt(nil, enc, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	return dec
}

// File Encryption/Decryption with Ascon80pq + RSA Key Wrap

func encryptAscon80pqfile(in io.Reader, out io.Writer, ad, nonce, key []byte) error {
	ascon80pq.Encrypt(out, in, ad, nonce, key)
	return nil
}

func EncryptFile(plainFile, encFile, filename, mime string, nonce, asconKey []byte, pub *rsa.PublicKey) error {
	in, err := os.Open(plainFile)
	if err != nil {
		return err
	}
	defer in.Close()

	normalized := normalizeTextReader(in)

	out, err := os.Create(encFile)
	if err != nil {
		return err
	}
	defer out.Close()

	ad := []byte("filename=" + filename + ";mime=" + mime)

	wrappedKey := RSAEncrypt(pub, asconKey)

	out.Write([]byte("ASC80PQv1"))
	out.Write(nonce)

	adLen := make([]byte, 4)
	binary.BigEndian.PutUint32(adLen, uint32(len(ad)))
	out.Write(adLen)
	out.Write(ad)

	wkLen := make([]byte, 2)
	binary.BigEndian.PutUint16(wkLen, uint16(len(wrappedKey)))
	out.Write(wkLen)
	out.Write(wrappedKey)

	return encryptAscon80pqfile(normalized, out, ad, nonce, asconKey)
}

func DecryptFile(encFile, returnFile string, priv *rsa.PrivateKey) (string, error) {
	in, err := os.Open(encFile)
	if err != nil {
		return "", err
	}
	defer in.Close()

	marker := make([]byte, 9)
	if _, err := io.ReadFull(in, marker); err != nil || string(marker) != "ASC80PQv1" {
		return "", fmt.Errorf("bad marker")
	}

	nonce := make([]byte, NonceSize)
	io.ReadFull(in, nonce)

	adLenBytes := make([]byte, 4)
	io.ReadFull(in, adLenBytes)
	adLen := binary.BigEndian.Uint32(adLenBytes)

	ad := make([]byte, adLen)
	io.ReadFull(in, ad)

	wkLenBytes := make([]byte, 2)
	io.ReadFull(in, wkLenBytes)
	wkLen := binary.BigEndian.Uint16(wkLenBytes)

	wrappedKey := make([]byte, wkLen)
	io.ReadFull(in, wrappedKey)

	asconKey := RSADecrypt(priv, wrappedKey) //decrypt the symmetric key

	ctWithTag, err := io.ReadAll(in)
	if err != nil {
		return "", err
	}

	packet := append(append([]byte{}, nonce...), ctWithTag...) // prepend nonce to ciphertext for decryption
	// the packet is how the nonce + ciphertext + is passed to decryption function due to libary constraints on arguements taken

	plaintext, err := decryptAscon80pq(packet, ad, asconKey)
	if err != nil {
		return "", err
	}

	out, err := os.Create(returnFile)
	if err != nil {
		return "", err
	}
	defer out.Close()

	out.Write(plaintext)

	return returnFile, nil
}

//  Client Encryption/Decryption

func EncryptForClient(plainFile, encFile, filename, mime string, clientCert *x509.Certificate) error {

	asconKey := mustRand(KeySize80pq)
	nonce := mustRand(NonceSize)

	clientPub, ok := clientCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("client certificate does not contain RSA public key")
	}

	return EncryptFile(plainFile, encFile, filename, mime, nonce, asconKey, clientPub)

}

func DecryptForClient(encFile, outFile string, clientPriv *rsa.PrivateKey) (string, error) {

	return DecryptFile(encFile, outFile, clientPriv)

}

// Tests
func printMem(label string) {
	var m runtime.MemStats // gets all the memory statistics
	runtime.ReadMemStats(&m)

	fmt.Printf("%s\n", label)
	fmt.Printf("  Alloc:       %d MB\n", m.Alloc/1024/1024)
	fmt.Printf("  TotalAlloc:  %d MB\n", m.TotalAlloc/1024/1024)
	fmt.Printf("  Sys:         %d MB\n", m.Sys/1024/1024)
	fmt.Printf("  NumGC:       %d\n", m.NumGC)
}

func testSingleFileTransfer(inputPath string) { // a collective call i can use to test files
	fmt.Println("Running single‑file transfer test")

	// build PKI
	rootCert, interCert, rootPriv, interPriv, err := buildT2PKI()
	if err != nil {
		panic(err)
	}

	// issue ClientA
	clientACert, clientAPriv, err := IssueClientCert(
		"ClientA",
		newSerial().Int64(),
		interCert,
		interPriv,
	)
	if err != nil {
		panic(err)
	}

	// output paths
	cipherPath := "cipher_output.asc"
	decryptedPath := "decrypted_output.bin"

	// encrypt for ClientA
	err = EncryptForClient(
		inputPath,
		cipherPath,
		inputPath,
		"application/octet-stream",
		clientACert,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Encrypted for ClientA")

	// load CRL (fresh, no revocations)
	crl, err := loadCRL()
	if err != nil {
		panic(err)
	}

	// verify ClientA
	err = verifyLeafWithPKI(clientACert, interCert, rootCert, crl)
	if err != nil {
		panic(err)
	}
	fmt.Println("ClientA certificate verified")

	// decrypt
	out, err := DecryptForClient(cipherPath, decryptedPath, clientAPriv)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted output file:", out)
	fmt.Println("Single‑file transfer test complete")

	_ = rootPriv
}

// Negitive testing suite(ish)

func mustKey() *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("keygen failed: " + err.Error())
	}
	return priv
}

func encryptTestRSA(pub *rsa.PublicKey, key []byte) []byte {
	return RSAEncrypt(pub, key)
}

func decryptTestRSA(priv *rsa.PrivateKey, ciphertext []byte) (dec []byte, err error) {
	defer func() {
		if r := recover(); r != nil { // uses recover to control the panic error
			err = fmt.Errorf("RSA decrypt panic: %v", r)
		}
	}()

	dec = RSADecrypt(priv, ciphertext)
	return dec, nil
}

// RSA NEGATIVE TESTS

func testRSACorruptedCiphertext() {
	fmt.Println("[RSA] Corrupted ciphertext test")

	priv := mustKey()
	pub := &priv.PublicKey

	key := []byte("test-key")
	enc := encryptTestRSA(pub, key)

	enc[3] ^= 0xFF // corrupt

	_, err := decryptTestRSA(priv, enc)
	if err == nil {
		panic("[FAIL] RSA corrupted ciphertext decrypted successfully")
	}

	fmt.Println("[PASS] RSA corrupted ciphertext rejected")
}

func testRSAWrongKey() {
	fmt.Println("[RSA] Wrong key test")

	priv1 := mustKey()
	priv2 := mustKey()

	key := []byte("test-key")
	enc := encryptTestRSA(&priv1.PublicKey, key)

	_, err := decryptTestRSA(priv2, enc)
	if err == nil {
		panic("[FAIL] RSA decrypted with wrong key")
	}

	fmt.Println("[PASS] RSA wrong key rejected")
}

func testRSATruncatedCiphertext() {
	fmt.Println("[RSA] Truncated ciphertext test")

	priv := mustKey()
	pub := &priv.PublicKey

	key := []byte("test-key")
	enc := encryptTestRSA(pub, key)

	truncated := enc[:len(enc)/2]

	_, err := decryptTestRSA(priv, truncated)
	if err == nil {
		panic("[FAIL] RSA truncated ciphertext decrypted successfully")
	}

	fmt.Println("[PASS] RSA truncated ciphertext rejected")
}

func testRSAEmptyCiphertext() {
	fmt.Println("[RSA] Empty ciphertext test")

	priv := mustKey()

	_, err := decryptTestRSA(priv, []byte{})
	if err == nil {
		panic("[FAIL] RSA empty ciphertext decrypted successfully")
	}

	fmt.Println("[PASS] RSA empty ciphertext rejected")
}

// ASCON NEGATIVE TESTS

func testAsconCorruptedCiphertext() {
	fmt.Println("[ASCON] Corrupted ciphertext test")

	key := 20
	nonce := 16
	tkey := mustRand(key)
	tnonce := mustRand(nonce)

	plaintext := bytes.Repeat([]byte("A"), 1024)
	ad := []byte{}

	ciphertext, err := encryptAscon80pq(plaintext, ad, tkey, tnonce)
	if err != nil {
		panic("[FAIL] Ascon encrypt failed: " + err.Error())
	}

	corruptIndex := 16 + 100
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)

	corrupt := append(corrupted, ciphertext...)

	corrupt[corruptIndex] ^= 0xAA

	_, err = decryptAscon80pq(corrupt, ad, tkey)

	if err != nil {
		fmt.Println("[PASS] Ascon corrupted ciphertext rejected")
		return
	}

	panic("[FAIL] Ascon corrupted ciphertext decrypted successfully")

}

// HYBRID NEGATIVE TEST

func testHybridCorruptedEncKey() {
	fmt.Println("[HYBRID] Corrupted RSA-wrapped Ascon key test")

	priv := mustKey()
	pub := &priv.PublicKey

	asconKey := []byte("1234567890ABCDEF")

	encKey := encryptTestRSA(pub, asconKey)

	encKey[0] ^= 0xFF // corrupt RSA-wrapped key

	_, err := decryptTestRSA(priv, encKey)
	if err == nil {
		panic("[FAIL] accepted corrupted RSA-wrapped key")
	}

	fmt.Println("[PASS] rejected corrupted RSA-wrapped key")
}

// PKI TESTING

func testRootCASelfConsistency() {
	fmt.Println("[PKI] Root CA self-consistency test")

	rootCert, _, rootPriv, _, err := buildT2PKI()
	if err != nil {
		panic("[FAIL] buildT2PKI failed in RootCA test: " + err.Error())
	}

	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		panic("[FAIL] Root CA cannot verify its own signature: " + err.Error())
	}

	if len(rootCert.SubjectKeyId) == 0 {
		panic("[FAIL] Root CA SKID is empty")
	}

	fmt.Println("[PASS] Root CA self-signature and SKID look valid")
	_ = rootPriv
}

func testIntermediateChain() {
	fmt.Println("[PKI] Intermediate chain test")

	rootCert, interCert, _, _, err := buildT2PKI()
	if err != nil {
		panic("[FAIL] buildT2PKI failed in Intermediate test: " + err.Error())
	}

	if err := interCert.CheckSignatureFrom(rootCert); err != nil {
		panic("[FAIL] Intermediate CA signature invalid: " + err.Error())
	}

	if len(interCert.SubjectKeyId) == 0 {
		panic("[FAIL] Intermediate CA SKID is empty")
	}
	if len(interCert.AuthorityKeyId) == 0 {
		panic("[FAIL] Intermediate CA AKID is empty")
	}

	fmt.Println("[PASS] Intermediate CA chain and AKID look valid")
}

func testLeafCertificate() {
	fmt.Println("[PKI] Leaf certificate chain test")

	rootCert, interCert, _, interPriv, err := buildT2PKI()
	if err != nil {
		panic("[FAIL] buildT2PKI failed in Leaf test: " + err.Error())
	}

	leafCert, _, err := IssueClientCert("test-client", 1001, interCert, interPriv)
	if err != nil {
		panic("[FAIL] IssueClientCert failed: " + err.Error())
	}

	if err := leafCert.CheckSignatureFrom(interCert); err != nil {
		panic("[FAIL] Leaf signature invalid: " + err.Error())
	}

	if len(leafCert.SubjectKeyId) == 0 {
		panic("[FAIL] Leaf SKID is empty")
	}
	if len(leafCert.AuthorityKeyId) == 0 {
		panic("[FAIL] Leaf AKID is empty")
	}

	if err := verifyLeafWithPKI(leafCert, interCert, rootCert, &x509.RevocationList{}); err != nil {
		panic("[FAIL] verifyLeafWithPKI failed for valid leaf: " + err.Error())
	}

	fmt.Println("[PASS] Leaf certificate chain and SKID/AKID look valid")
}

func testRevocation() {
	fmt.Println("[PKI] Revocation test")

	rootCert, interCert, _, interPriv, err := buildT2PKI()
	if err != nil {
		panic("[FAIL] buildT2PKI failed in Revocation test: " + err.Error())
	}

	leafCert, _, err := IssueClientCert("revoked-client", 2001, interCert, interPriv)
	if err != nil {
		panic("[FAIL] IssueClientCert failed in Revocation test: " + err.Error())
	}

	// Builds a minimal inmemory revocation list that includes the leaf
	crl := &x509.RevocationList{
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   leafCert.SerialNumber,
				RevocationTime: time.Now(),
			},
		},
	}

	err = verifyLeafWithPKI(leafCert, interCert, rootCert, crl)
	if err == nil {
		panic("[FAIL] Revoked leaf was accepted by verifyLeafWithPKI")
	}

	fmt.Println("[PASS] Revoked leaf correctly rejected by verifyLeafWithPKI")
}

func testWrongIssuer() {
	fmt.Println("[PKI] Wrong issuer test")

	rootCert, interCert, rootPriv, interPriv, err := buildT2PKI()
	if err != nil {
		panic("[FAIL] buildT2PKI failed in WrongIssuer test: " + err.Error())
	}

	// Issues a valid leaf from the real intermediate
	leafCert, _, err := IssueClientCert("wrong-issuer-client", 3001, interCert, interPriv)
	if err != nil {
		panic("[FAIL] IssueClientCert failed in WrongIssuer test: " + err.Error())
	}

	// Builds a second false intermediate signed by the same root
	wrongPriv, wrongPub := RSAKeyGen()
	profile := IntermediateCAProfile()
	wrongTemplate := BuildCertTemplateFromProfile(profile, "Wrong Intermediate CA", big.NewInt(99))

	wrongSKID, err := buildSKID(wrongPub)
	if err != nil {
		panic("[FAIL] buildSKID failed in WrongIssuer test: " + err.Error())
	}
	wrongAKID, err := buildAKID(rootCert.PublicKey)
	if err != nil {
		panic("[FAIL] buildAKID failed in WrongIssuer test: " + err.Error())
	}
	wrongTemplate.SubjectKeyId = wrongSKID
	wrongTemplate.ExtraExtensions = append(wrongTemplate.ExtraExtensions,
		pkix.Extension{
			Id:    []int{2, 5, 29, 14},
			Value: wrongSKID,
		},
		pkix.Extension{
			Id:    []int{2, 5, 29, 35},
			Value: wrongAKID,
		},
	)

	wrongDER, err := createCert(wrongTemplate, rootCert, wrongPub, rootPriv)
	if err != nil {
		panic("[FAIL] createCert failed for wrong intermediate: " + err.Error())
	}
	wrongIntermediate, err := x509.ParseCertificate(wrongDER)
	if err != nil {
		panic("[FAIL] ParseCertificate failed for wrong intermediate: " + err.Error())
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inters := x509.NewCertPool()
	inters.AddCert(wrongIntermediate)

	opts := x509.VerifyOptions{
		Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leafCert.Verify(opts); err == nil {
		panic("[FAIL] Leaf incorrectly verified against wrong intermediate")
	}

	fmt.Println("[PASS] Leaf correctly rejected when chained to wrong issuer")
	_ = wrongPriv
}

func testExpiry() {
	fmt.Println("[PKI] Expiry test")

	rootCert, interCert, _, interPriv, err := buildT2PKI()
	if err != nil {
		panic("[FAIL] buildT2PKI failed in Expiry test: " + err.Error())
	}

	// Build an expired client profile
	expiredProfile := ClientProfile()
	expiredProfile.Validity = -1 * time.Hour // already expired

	tmpl := BuildCertTemplateFromProfile(expiredProfile, "expired-client", big.NewInt(4001))

	clientPriv, clientPub := RSAKeyGen()

	clientSKID, err := buildSKID(clientPub)
	if err != nil {
		panic("[FAIL] buildSKID failed in Expiry test: " + err.Error())
	}
	clientAKID, err := buildAKID(interCert.PublicKey)
	if err != nil {
		panic("[FAIL] buildAKID failed in Expiry test: " + err.Error())
	}
	tmpl.SubjectKeyId = clientSKID
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions,
		pkix.Extension{
			Id:    []int{2, 5, 29, 14},
			Value: clientSKID,
		},
		pkix.Extension{
			Id:    []int{2, 5, 29, 35},
			Value: clientAKID,
		},
	)

	der, err := createCert(tmpl, interCert, clientPub, interPriv)
	if err != nil {
		panic("[FAIL] createCert failed in Expiry test: " + err.Error())
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		panic("[FAIL] ParseCertificate failed in Expiry test: " + err.Error())
	}

	err = verifyLeafWithPKI(leafCert, interCert, rootCert, &x509.RevocationList{})
	if err == nil {
		panic("[FAIL] Expired certificate was accepted by verifyLeafWithPKI")
	}

	fmt.Println("[PASS] Expired certificate correctly rejected")
	_ = clientPriv
}

func sideChannelPKI() {
	fmt.Println(" Sidechannel: PKI timing ")

	// Build PKI once
	rootCert, interCert, _, interPriv, err := buildT2PKI()
	if err != nil {
		panic("buildT2PKI failed: " + err.Error())
	}

	// VALID LEAF
	validLeaf, _, err := IssueClientCert("sc-valid", 5001, interCert, interPriv)
	if err != nil {
		panic("IssueClientCert (valid) failed: " + err.Error())
	}

	// REVOKED LEAF
	revokedLeaf, _, err := IssueClientCert("sc-revoked", 5002, interCert, interPriv)
	if err != nil {
		panic("IssueClientCert (revoked) failed: " + err.Error())
	}

	// Builds a CRL that revokes the second leaf
	revokedCRL := &x509.RevocationList{
		RevokedCertificates: []pkix.RevokedCertificate{
			{SerialNumber: revokedLeaf.SerialNumber, RevocationTime: time.Now()}},
	}

	// TIMING VALID CERT
	timeOp("PKI valid cert", 500, func() error {
		return verifyLeafWithPKI(validLeaf, interCert, rootCert, &x509.RevocationList{})
	})

	// TIMING REVOKED CERT
	timeOp("PKI revoked cert", 500, func() error {
		return verifyLeafWithPKI(revokedLeaf, interCert, rootCert, revokedCRL)
	})

	fmt.Println(" PKI sidechannel timing complete ")
}

func sidechannelRSA() {
	fmt.Println(" Sidechannel: RSA-OAEP timing ")

	privA, pubA := RSAKeyGen()
	privB, _ := RSAKeyGen()

	msg := []byte("sidechannel-test")
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubA, msg, nil)
	if err != nil {
		panic("RSA encrypt failed: " + err.Error())
	}

	timeOp("RSA correct key", 1000, func() error {
		_, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privA, ct, nil)
		return err
	})

	timeOp("RSA wrong key", 1000, func() error {
		_, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privB, ct, nil)
		return err
	})
}

func sidechannelAscon() {
	fmt.Println(" Sidechannel Ascon timing ")

	key := make([]byte, 20)
	nonce := make([]byte, 16)
	rand.Read(key)
	rand.Read(nonce)

	pt := bytes.Repeat([]byte("A"), 1024)
	ad := []byte("hdr")

	ct, err := encryptAscon80pq(pt, ad, key, nonce)
	if err != nil {
		panic("Ascon encrypt failed: " + err.Error())
	}

	corrupted := make([]byte, len(ct))
	copy(corrupted, ct)
	corrupted[len(corrupted)-1] ^= 0xAA

	timeOp("Ascon valid", 2000, func() error {
		_, err := decryptAscon80pq(ct, ad, key)
		return err
	})

	timeOp("Ascon corrupted", 2000, func() error {
		_, err := decryptAscon80pq(corrupted, ad, key)
		return err
	})
}

// RUN ALL TESTS

func RunAllNegativeTests() {
	fmt.Println(" RUNNING NEGATIVE TEST SUITE ")

	// RSA
	testRSACorruptedCiphertext()
	testRSAWrongKey()
	testRSATruncatedCiphertext()
	testRSAEmptyCiphertext()

	// ASCON
	testAsconCorruptedCiphertext()

	// HYBRID
	testHybridCorruptedEncKey()

	fmt.Println("=== ALL NEGATIVE TESTS PASSED ===")
}

func RunAllPKITests() {
	fmt.Println(" RUNNING PKI TEST SUITE ")

	testRootCASelfConsistency()
	testIntermediateChain()
	testLeafCertificate()
	testRevocation()
	testWrongIssuer()
	testExpiry()

	fmt.Println(" ALL PKI TESTS PASSED ")
}

func RunSideChannelTests() {
	fmt.Println(" RUNNING SIDECHANNEL TESTS ")
	sideChannelPKI()
	sidechannelRSA()
	sidechannelAscon()

	fmt.Println("ALL SIDECHANNEL TESTS COMPLETE ")
}

func main() {

	//fmt.Println("DEBUG: starting main")

	// Builds PKI (Root + Intermediate)

	fmt.Println(" Building PKI")
	printMem("Before system run")

	SystemTimeStart := time.Now()
	rootCert, interCert, rootPriv, interPriv, err := buildT2PKI()
	if err != nil {
		panic(err)
	}
	_ = rootPriv
	//fmt.Printf(" Root CA: %s\n", rootCert.Subject.CommonName)
	//fmt.Printf(" Intermediate CA: %s\n", interCert.Subject.CommonName)

	// Issues two independent client certificates

	fmt.Println(" Issuing client certificates")

	clientACert, clientAPriv, err := IssueClientCert("ClientA", newSerial().Int64(), interCert, interPriv)
	if err != nil {
		panic(err)
	}
	fmt.Println("Issued ClientA")

	clientBCert, clientBPriv, err := IssueClientCert("ClientB", newSerial().Int64(), interCert, interPriv)
	if err != nil {
		panic(err)
	}
	fmt.Println(" Issued ClientB")

	os.WriteFile("plainA.txt", []byte("message for client A"), 0600)
	os.WriteFile("plainB.txt", []byte("message for client B"), 0600)

	//  Encrypting files for each client
	printMem("Before encryption")
	ClientEncryptTimeStart := time.Now()
	if err := EncryptForClient("plainA.txt", "cipherA.asc", "plainA.txt", "text/plain", clientACert); err != nil {
		panic(err)
	}

	if err := EncryptForClient("plainB.txt", "cipherB.asc", "plainB.txt", "text/plain", clientBCert); err != nil {
		panic(err)
	}
	printMem("After encryption")
	ClientEncryptTimeElasped := time.Since(ClientEncryptTimeStart)
	fmt.Printf("Client Encryption Time Elapsed: %s\n", ClientEncryptTimeElasped)

	// Loads  CRL and verify

	fmt.Println("Verifying and decrypting for each client")

	crl, err := loadCRL()
	if err != nil {
		panic(err)
	}

	// Client A
	if err := verifyLeafWithPKI(clientACert, interCert, rootCert, crl); err != nil {
		panic(fmt.Errorf("ClientA verify failed: %w", err))
	}
	//  decrypt for each client
	printMem("Before decryption")
	ClientDecryptTimeStart := time.Now()
	outA, err := DecryptForClient("cipherA.asc", "decryptedA.txt", clientAPriv)
	if err != nil {
		panic(err)
	}
	fmt.Println("ClientA verified and decrypted", outA)

	// Client B
	if err := verifyLeafWithPKI(clientBCert, interCert, rootCert, crl); err != nil {
		panic(fmt.Errorf("ClientB verify failed: %w", err))
	}
	//  decrypt for each client
	outB, err := DecryptForClient("cipherB.asc", "decryptedB.txt", clientBPriv)
	if err != nil {
		panic(err)
	}
	printMem("after decryption")
	ClientDecryptTimeElasped := time.Since(ClientDecryptTimeStart)
	fmt.Printf("Client Decryption Time Elapsed: %s\n", ClientDecryptTimeElasped)
	fmt.Println("ClientB verified and decrypted ", outB)

	// Revoke ClientA

	fmt.Println(" Revoking ClientA")
	if err := revokeCert(clientACert, interCert, interPriv); err != nil {
		panic(err)
	}
	crl, err = loadCRL()
	if err != nil {
		panic(err)
	}
	fmt.Println("ClientA revoked")

	// Post‑revocation verification

	fmt.Print("    - ClientA: ")
	if err := verifyLeafWithPKI(clientACert, interCert, rootCert, crl); err != nil {
		fmt.Println("verification fails as expected")
	} else {
		fmt.Println("BUG: still verifies (should be revoked)")
	}

	fmt.Print("    - ClientB: ")
	if err := verifyLeafWithPKI(clientBCert, interCert, rootCert, crl); err != nil {
		fmt.Println("BUG: verification failed after revoking A")
	} else {
		fmt.Println("still valid")
		outB2, err := DecryptForClient("cipherB.asc", "decryptedB_after.txt", clientBPriv)
		if err != nil {
			panic(err)
		}
		fmt.Println(" ClientB decrypted again ->", outB2)
	}
	printMem("After system run")
	SystemTimeElasped := time.Since(SystemTimeStart)
	fmt.Printf("Total System Time Elapsed: %s\n", SystemTimeElasped)

	// In-memory Ascon test
	InMemoryAsconTimeStart := time.Now()
	asconKey := mustRand(KeySize80pq)
	memNonce := mustRand(NonceSize)
	ad := []byte("header:version=1;type=demo")
	plaintext := []byte("this is a bugger")

	ciphertext, _ := encryptAscon80pq(plaintext, ad, asconKey, memNonce)
	packet := append(append([]byte{}, memNonce...), ciphertext...)
	recovered, err := decryptAscon80pq(packet, ad, asconKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("In-memory Ascon decrypted:", string(recovered))
	InMemoryAsconTimeElasped := time.Since(InMemoryAsconTimeStart)
	fmt.Printf("In-memory Ascon Time Elapsed: %s\n", InMemoryAsconTimeElasped)

	// Single-larger-file timed transfer test

	//printMem("Before 100MB file")
	//OneHundredMBTimeStart := time.Now()
	//testSingleFileTransfer("100MB.bin")
	//OneHundredMBTimeElasped := time.Since(OneHundredMBTimeStart)
	//fmt.Printf("100MB File Transfer Time Elapsed: %s\n", OneHundredMBTimeElasped)
	//printMem("After 100MB file")

	//printMem("Before 1GB file")
	//OneGBTimeStart := time.Now()
	//testSingleFileTransfer("1GB.bin")
	//OneGBTimeElasped := time.Since(OneGBTimeStart)
	//fmt.Printf("1GB File Transfer Time Elapsed: %s\n", OneGBTimeElasped)
	//printMem("After 1GB file")

	// Test Suite Triggers
	RunAllNegativeTests()
	RunAllPKITests()
	RunSideChannelTests()

}
