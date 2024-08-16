package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	errors2 "github.com/pkg/errors"

	"github.com/casdoor/casdoor/orm"
)

const (
	ScopeCertJWT    = "JWT"
	ScopeCertCACert = "CA Certificate"
	ScopeClientCert = "Client Certificate"
)

func GetCertByName(name string) (*Cert, error) {
	if name == "" {
		return nil, nil
	}

	cert := Cert{Name: name}
	existed, err := orm.AppOrmer.Engine.Get(&cert)
	if err != nil {
		return &cert, nil
	}

	if existed {
		return &cert, nil
	} else {
		return nil, nil
	}
}

func GetTlsConfigForCert(name string) (*tls.Config, error) {
	cert, err := GetCertByName(name)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, ErrCertDoesNotExist
	}

	ca := x509.NewCertPool()
	if ok := ca.AppendCertsFromPEM([]byte(cert.Certificate)); !ok {
		return nil, ErrX509CertsPEMParse
	}

	return &tls.Config{RootCAs: ca}, nil
}

var ErrCertDoesNotExist = errors.New(fmt.Sprintf("certificate does not exist"))
var ErrCertInvalidScope = errors.New(fmt.Sprintf("invalid certificate scope"))

var ErrX509CertsPEMParse = errors2.New("x509: malformed CA certificate")

type Cert struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	DisplayName     string `xorm:"varchar(100)" json:"displayName"`
	Scope           string `xorm:"varchar(100)" json:"scope"`
	Type            string `xorm:"varchar(100)" json:"type"`
	CryptoAlgorithm string `xorm:"varchar(100)" json:"cryptoAlgorithm"`
	BitSize         int    `json:"bitSize"`
	ExpireInYears   int    `json:"expireInYears"`

	Certificate string `xorm:"mediumtext" json:"certificate"`
	PrivateKey  string `xorm:"mediumtext" json:"privateKey"`
}

func (p *Cert) GetId() string {
	return fmt.Sprintf("%s/%s", p.Owner, p.Name)
}
