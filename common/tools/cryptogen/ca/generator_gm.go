package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/hyperledger/fabric/bccsp/gm"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
	"strings"
	"io/ioutil"

	//"github.com/hyperledger/fabric/bccsp/utils"
	x509GM "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
)

// default template for X509 certificates
func x509GMTemplate() x509GM.Certificate {
	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// set expiry to around 10 years
	expiry := 3650 * 24 * time.Hour
	// round minute and backdate 5 minutes
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()

	//basic template to use
	x509 := x509GM.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		SignatureAlgorithm:    x509GM.SM2WithSM3,
		BasicConstraintsValid: true,
	}
	return x509
}

// generate a signed X509 certificate using SM2
func genCertificateSM2(baseDir, name string, template, parent *x509GM.Certificate, pub *sm2.PublicKey,
	signer crypto.Signer) (*x509GM.Certificate, error) {

	//create the x509 public cert
	certBytes, err := x509GM.CreateCertificate(template, parent, pub, signer)

	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	//pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509GM.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return x509Cert, nil
}

//LoadCertificateSM2
func LoadCertificateSM2(certPath string) (*x509GM.Certificate, error) {
	var cert *x509GM.Certificate
	var err error

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pem") {
			rawCert, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(rawCert)
			cert,err =x509GM.ParseCertificate(block.Bytes)
		}
		return nil
	}

	err = filepath.Walk(certPath, walkFunc)
	if err != nil {
		return nil, err
	}

	return cert, err
}


func (ca *CA) SignGMCertificate(baseDir, name string, ous, sans []string, pub *sm2.PublicKey,
	ku x509GM.KeyUsage, eku []x509GM.ExtKeyUsage) (*x509.Certificate, error) {

	template := x509GMTemplate()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	//set the organization for the subject
	subject := subjectTemplateAdditional(ca.Country, ca.Province, ca.Locality, ca.OrganizationalUnit, ca.StreetAddress, ca.PostalCode)
	subject.CommonName = name

	subject.OrganizationalUnit = append(subject.OrganizationalUnit, ous...)

	template.Subject = subject
	for _, san := range sans {
		// try to parse as an IP address first
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	cert, err := genCertificateSM2(baseDir, name, &template, gm.ParseX509Certificate2Sm2(ca.SignCert),
		pub, ca.Signer)

	if err != nil {
		return nil, err
	}

	return gm.ParseSm2Certificate2X509(cert), nil
}

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewGMCA(baseDir, org, name, country, province, locality, orgUnit, streetAddress, postalCode string) (*CA, error) {
	var response error
	var ca *CA

	err := os.MkdirAll(baseDir, 0755)
	if err == nil {
		priv, signer, err := csp.GenerateSM2PrivateKey(baseDir)
		response = err
		if err == nil {
			// get public signing certificate
			ecPubKey, err := csp.GetSM2PublicKey(priv)
			response = err
			if err == nil {
				template := x509GMTemplate()
				//this is a CA
				template.IsCA = true
				template.KeyUsage |= x509GM.KeyUsageDigitalSignature |
					x509GM.KeyUsageKeyEncipherment | x509GM.KeyUsageCertSign |
					x509GM.KeyUsageCRLSign
				template.ExtKeyUsage = []x509GM.ExtKeyUsage{
					x509GM.ExtKeyUsageClientAuth,
					x509GM.ExtKeyUsageServerAuth,
				}

				//set the organization for the subject
				subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
				subject.Organization = []string{org}
				subject.CommonName = name

				template.Subject = subject
				template.SubjectKeyId = priv.SKI()

				x509Cert, err := genCertificateSM2(baseDir, name, &template, &template,
					ecPubKey, signer)
				response = err
				if err == nil {
					ca = &CA{
						Name:               name,
						Signer:             signer,
						SignCert:           gm.ParseSm2Certificate2X509(x509Cert),
						Country:            country,
						Province:           province,
						Locality:           locality,
						OrganizationalUnit: orgUnit,
						StreetAddress:      streetAddress,
						PostalCode:         postalCode,
					}
				}
			}
		}
	}
	return ca, response
}

