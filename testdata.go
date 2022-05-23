package main

import (
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/kubasiemion/x509PQexpansion/x509"
)

func GetTemplate() *x509.Certificate {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"San Lab"},
			Country:       []string{"ES"},
			Province:      []string{"Madrid"},
			Locality:      []string{"Madrid"},
			StreetAddress: []string{"Santander Ciudad de Financiera"},
			PostalCode:    []string{"28266"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return ca
}

const rsa4096privPem = `-----BEGIN PRIVATE KEY-----
MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCzdkb71OXQbs+m
DBumyVeIVrFikXQFc5yJQQuBA3RcjIDqOmsJyqoWMsi8wbc9BTmxQk131J7bDy0+
Sn4Mk8BMiQs573a9ruwpBaLi2DyphksUrhsSqzjFYs4GlI5FVbLV6G1A73W/sbLk
Hmmh/a0rPaujPFZH1sHIeR1YvPVjAL8lPn7La/3wADRTnsCPqHDRawOMNDM5upHQ
cjAXXD6VCs/shovltOCrJzVHC43dh/9Ka2nEB1odT8lhSEKkWPeAEDlORPQkDyC+
D+kIHpRMWF95aUebJmSoViRAh7dv/kzLY5AHPlujTEJXF0EnFwWa+xZJfXTxCASG
5259QSpLfINji7YKH7uTLeHoMfEUutDDm98tyR2VL6Ws/wSHf12nkLt3ok9i1onq
2OHqNmxyTnu4qS0AKuSepMT2dcqQJQexWnwV6UR+WUkEZZ1blsnFb/CkjW7i0glb
tefS72ZIkfxmSfO5Z0CO4qFAI/3o9WIqsuez99NUeXEEZ9xwk2HfL8z9Lj0Ae+cS
zpfOuE2GEk9XYnZgzxzYqzinXeZNOY0GW+swwW3QqQglowYWhni/stwABinBc2Ym
ogxAnsCvheyobLZmvTnbohuFh1ZlxPm8I3KGyJmUGvoVjaoUFOb/aErt6aMI/KSm
dvA7F0SJAgxKSyfiDKUS9pLBv1Y5mQIDAQABAoICAQCqg14MlwtIkJDxhx2aykFG
BIEEU4l2SJPaAZhpm5uq98DhTGI5antTHiuG1VRCQT3Aw2uRyM6q+u+U+PhtANG8
ppWpFXKv5YzzqSxL9wMkW7noy0hj45XMTgXNUMcg770861srUJqDada8Un0xcjNg
G3eCYKjmFxIGZbVRhDBvQd1cCNY2d8ROjhMpxHPXy0ZuZAx54XsuhatX77br6zR3
Lk/Cv1AbEFJLrLQ9baf8beRNlGNo40dnBFEmAp93QiTfZAre6DtEK6+DhuB2W3+y
TmFgnXxw2PjYzQgi3BCZ83iJ426Mw14UeTerQiggeQpVZ+6UIwTCo0iR2UEs94az
m+baE/6IyED8ElMyEA5P1iJirRSu/D1lSSB/4DfUZ7VBNo/kdlTR8lla3ClIi8WF
zEqM57Trt74LcFRbUphwJapr6X4X65H4s03WDjC2i70KiaeM6fVsdNldSOFXH02p
mNLBOC21dh1KCqKpP+EZnuWXCBe/QKACgS/VtV4zqrQBxK4AeY2YVCRTfCf2cse4
AoS1PORv/wnTOrWjx5r1S8exh+GGjl6f8iU7jkw2jNCohFi9yw/M5rWc+Kzgu+ve
+XJXTsC40tVv26b3+LOCUOb3lboFWpEEFSEBEnmJD7isVDUy/dV5ITIMYz3OxXoR
xzGQZKSEPNNcTlVz+uWhkQKCAQEA5+JSbkayrYt65fo2JPxYH6q1DZVgigjh2H19
UKTSBBeqzBz1xQ52P4SJKRnmpl4/W6G1FPg2PBmAinQijryPiscIVfvD4O6+rSI3
NV4OrTQCe6zawBe4biV9g/shxkUkjauBGoea6HTlHu1yhHElbk2hVP2njkX2Uw5K
2sdoAexf0GIqmzSONHPwEoJbg83UMXDVH3o7z6FtHwDygk36Y3RqVz176sfjoNYu
O8Ih8E+cNp7FhJ3GuaZAmkK1vjLDKJ2yo3TKRoFOFHPu4gqMm45WUjDde526KALr
EV9K5DPuiblqGvHYSAbdy6O+ykh4l2AS9sPxxW/vfW9NlhSMPQKCAQEAxiBFe+hd
HtBU2Y86rlfxxjiCOO0SzuKBOycDubSdZ3eQiZgknxdXqDZ6A7s3i2Brqt4Fhs3u
5NEIaRyay00Oiw4l0DHKclz1abItgnF+vxoDcINSAxr1pHcjfPrniF29eCXAkCBM
PtKA51KuSiNqnWc0bT/6sQhRDyCRYTlr6Er5OLtcOA9oOnKMn/DZhG+qiOpZnrpD
WVZNmouwHdgJASLi2x03dsIFQIOCU6Ksgkx03tlnbxn+GDwuaTLUGS8BJCMJf7tH
lfotVrN1gsS72fUJ3RLc/x/c3hBWhc2NdjRVgI9GAO/wh/jefXuZi+18GrAhtk6d
Q3So/EpsJ7ysjQKCAQANq/JgPhra0JZ2aMI4fAhWFaKHIn+Go+9s7DkvQAiB5UNU
tYBoFeoy5IWRvs0ykev6YxZiHiBUesxxXVeMQuHTtNhw+V8bK/hiDNpkcx86Zw6e
bBqZqMxe8ibsWSosnncBQ1NhVQ11Fy9LG4Tc+i7SyhDxCeOPJ+DWFMmlDIy9UEp1
5tPMQtT/krZc4QK0SrZwE879BB/ypfnhEhU6SY6xvnNmoWFk/lQVb4taSp/lo0v6
jHHo18SXvY2hir1ccXHAO0wFByXF8mnAGvXCrgyMP2AniGoGl84Z/dIOPCgWPFmc
FSqEXC38UStSjlz5YDx78FYt5m+izG66Xo2cg6mhAoIBAAZcUt6/fv3WQmMZrhCa
0jBC8CtTsR7jNrLndb8ohUUlGYbRU5un7DCCTzh/cjEPT2WU6yiAxAKkk1iMious
VaMxORWOA6nYQii6h6uAaUlJVILwNFnVK72z9Xe1tmkyWTraO2xlHQ2HRIwoo1/N
80ZKYex/+VRlp/SMXx538XbrsUSY/0TtebMmqk0YNmOCEj+DBo2J/U+I7cTgZy8O
GHvo2s+eCIHPiMuhbTWyK0ejnLzqzd9LPlUY2YSXFSgZ0jeOyGdJY+r0tS/rYwJn
voAo1cA7Ms0eAMFAVQbGqpv44iXWc7DkAxzaaIouxacwYKOas/peW74mqKYw3XgJ
HqECggEAMcSCcfyRK8GVLwWEMd4xlptsGbIVlZRHqMdqszs+/vqjyWRc7XNZys2d
jX1pNrMHNLewXZXlbcCkaW0apGVxKEcDe6PdMUAOLzECmH7UH5tm6qZIGLw74zpq
LpcmBHy812ZcT+sClHq59CVQPw23kgSsm1YGLGmJTiuh1Os0X2qJyh7XWuCrDFi7
bm6XWYadUzGGBR+JTGLaHEJHYV7B2Pia5lsJ1/fJcIhhB/3KgADNBQiUioHkSc/G
sSGnmVQNV4TxjQzVCn/U0w2K2SLsFtFcuPRBOqEyfHxqKv+DGpCw+s8vW39R2t0s
EtuUK8yhzS4Y0u0JVpWuzTXfWw5V7A==
-----END PRIVATE KEY-----`

const selfSignedRootCertRSA4096Pem = `-----BEGIN CERTIFICATE-----
MIIFmTCCA4GgAwIBAgIUJQVU9KI12jx6er35W2ZFQUf6DAEwDQYJKoZIhvcNAQEN
BQAwXDELMAkGA1UEBhMCRVMxDDAKBgNVBAgMA01hZDEPMA0GA1UEBwwGTWFkcmlk
MQ4wDAYDVQQKDAVTYW50YTENMAsGA1UECwwEQkNPRTEPMA0GA1UEAwwGU0FOTEFC
MB4XDTIyMDUwNjEwMDMxNVoXDTIzMDUwNjEwMDMxNVowXDELMAkGA1UEBhMCRVMx
DDAKBgNVBAgMA01hZDEPMA0GA1UEBwwGTWFkcmlkMQ4wDAYDVQQKDAVTYW50YTEN
MAsGA1UECwwEQkNPRTEPMA0GA1UEAwwGU0FOTEFCMIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEAs3ZG+9Tl0G7PpgwbpslXiFaxYpF0BXOciUELgQN0XIyA
6jprCcqqFjLIvMG3PQU5sUJNd9Se2w8tPkp+DJPATIkLOe92va7sKQWi4tg8qYZL
FK4bEqs4xWLOBpSORVWy1ehtQO91v7Gy5B5pof2tKz2rozxWR9bByHkdWLz1YwC/
JT5+y2v98AA0U57Aj6hw0WsDjDQzObqR0HIwF1w+lQrP7IaL5bTgqyc1RwuN3Yf/
SmtpxAdaHU/JYUhCpFj3gBA5TkT0JA8gvg/pCB6UTFhfeWlHmyZkqFYkQIe3b/5M
y2OQBz5bo0xCVxdBJxcFmvsWSX108QgEhudufUEqS3yDY4u2Ch+7ky3h6DHxFLrQ
w5vfLckdlS+lrP8Eh39dp5C7d6JPYtaJ6tjh6jZsck57uKktACrknqTE9nXKkCUH
sVp8FelEfllJBGWdW5bJxW/wpI1u4tIJW7Xn0u9mSJH8ZknzuWdAjuKhQCP96PVi
KrLns/fTVHlxBGfccJNh3y/M/S49AHvnEs6XzrhNhhJPV2J2YM8c2Ks4p13mTTmN
BlvrMMFt0KkIJaMGFoZ4v7LcAAYpwXNmJqIMQJ7Ar4XsqGy2Zr0526IbhYdWZcT5
vCNyhsiZlBr6FY2qFBTm/2hK7emjCPykpnbwOxdEiQIMSksn4gylEvaSwb9WOZkC
AwEAAaNTMFEwHQYDVR0OBBYEFCa5aGnXfksDj8DQI2qzTHwsezk6MB8GA1UdIwQY
MBaAFCa5aGnXfksDj8DQI2qzTHwsezk6MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQENBQADggIBAGYvzAATnUwo0oGPN6Z05fKEMoJNp4wcZtk+RmWjvOu4Vsl3
F0e7hHUU/29VPOSufovWzLvT06puvb2kX8w7R6YG1J85hS4qPFZvAIzaeF+EKEqj
8bygE/lsxNW41A4r6J3YEuN/tm47xG5llFgpNiVg+x1Jn8Vv72rYfB8gUuHmMgfa
h3toNGzrjgXXIWF/zRASY1NnmMyTyM51Y20T1wZ7F71jsiTcFaAvmKWnEAvY7E6a
6kpVA4ygP7+KjK9y7H0I7JqOM4RCxnVzpfzARFKqZusCjfUIYQo4ctz0MPPQxcXq
oKtuwMxoR0qj91XBYecqG+AjRCtmxyJ+YcV2kCXBWAT3hQdjb6T0VcrwiGy5jl5c
TkdLp5M5FiqZSPSmjR7b8nOnz85uAglHlBu9db73f5qxATAwFzLU+in4xwpZDMms
3eweTLykrpLig2DzJkHBVgz+YVzvBF62BMs3Z4xSy0jfwii3NipYJi58MQYStHgx
zMbNzYKQzv2+Jwt1YnFuvaNgBbKm3m2k1nq9kVX7AsYVXvMHZJvDbiU98T2rq87f
/JV4GjEvelKQ0UtYl0p78XDIkMD07xdEMT5Vemfm8jKq6r5wp9xZji2ADglgaI2J
UyeTDTpo3zdyrmyB8OCdKAfqK3JN481TmtEjkTmqKr8IuGX06ZClvZJ4ZmQW
-----END CERTIFICATE-----`

const intermediateRSA2048keyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu6fD69eB2CACTLZJdlZLqzYGl1R/05wgPQivW3ue1S71iGlu
OgNH2DGIAcQxIKIS3eZoCtCTJP3qGL0lhayu4jCbSUEgaUOcBr0OcnROSxIubVGe
K3R6SPCBW2YaGeICydM3EAF9f+JwUwBu0YLfN+y50XjzEAycWzdAL0N6ajtmvRrc
ywUY8FpaJbiMp/BtCb9ei63gis+WfLRtbAFKJJRCvszEHG7Xr4JAYZPjDsY0wfmc
5UkK+GMl9kvsBDWCLS1nSHTwJt/7SGiDJ1nygbP3Mdhe+a3I6kA1h8U/YuJXRdnY
pTaxPPQZOfYWeLNJbXhdUei9iafZypivZDNiDwIDAQABAoIBAAesfJ6QWYb1CCMK
8UYdkUqXEv3tPqzwnYDhcgpTq9Mb8H57kT5eE/oLTHyGAVxMRGk+mtKWZO4GVCRe
18H3pc8qHa+JMkIbua2s3YJgrzLys2NVCxrL0JRbAW8zZa3ZSDPopz/IT9GC+QTr
55w5tdcbnx2pzIbDfUFdqQpFwCPH6B8IWZo3i1cSmgw+IZtJePcZ9kobxlHUkpE/
eLdthm6gzKl0JOMNNnAB+7N54yctV11NbbugzN5D2pZGX2bJvpW6YoSqdg6x2kBW
ZziN41bxftdhBWymECMui9/uXdWTeX8MC+h83PZG16cuGf25UsLN4Ir4q208jkkF
PfBtDYECgYEA6BnG6RAd5/UGQzGVHnsq6No1zhJXMLvP5S5ghJR1SJpjXSnbSo7G
ts27qBMcu90mWfVIwW6rhduwROmd7UODm0rwhCU9gj3HOWQAw4V/hlH4jAqNGW54
Ua7Qry3XxLEVUZylqmUuUDNZV18pGLoDIPGcbqvpKsGNe9WbHyQDV4cCgYEAzvpm
O1FWOwxWRnFyWKR0G3A2hJ9Zs9u2rO3YsGXaKB3AP4oq8l7XXYSBduzhgUPq4jBX
KItjZRsZ9j5Cd8OkZcmxBNok1DM7DhnV1SD7rK4fvNZN3pooyB3CJXIq07oU8Y0p
9svNx+baYcHMHXmYbBn7tUECyHlk64/IK5oTMzkCgYEAqL4s5j8Ibx6uGeYPcyS6
8qXK3nJpH448PHQ2Sc2hY1KTkSUgQJmDEV6L40tZ5Z+IBXkWF0O9wkkRY1ixr9EY
+qtGJ9znVixSDoCNKZmCOIaZ/D6jjOzK3yAIqoPazi6swDPyIesD+90JREN0Hn0G
T0o5oCCuGZ60nWaUK9TD9TsCgYBmRlU9+nMhunbnWCeopZq59Dj8T8GDno4l5WGt
yKaELC9TNnMCUNsa2t8eZO8JcQYfvsNSxY3X6AxsIVe21nXl1kQioaiRMr97uEhx
iFrUeTY1ma/gz0xXllzZJBEFjm3K7nZN/Wcx4GEI7TpvViZ7RFuctQMrDNFRlTrU
UM4sAQKBgEg2t9rYRDMlU41909wa3Ov5xJ5lnysmzMjuG+F6MJhB5LPxsiv8OSvt
Uf+1chZDNVFRypn1B2Gjy+vWZSJebGfYO/yVTieeItzwq5uMyYbuxyAMKlIrSgCx
fcqyB3wcl4x5/jgtYLXXQ9osYf9ybUCyv4bukdSgmwlxfecmd88z
-----END RSA PRIVATE KEY-----`

const intermediateCertPem = `-----BEGIN CERTIFICATE-----
MIIEwDCCAqigAwIBAgIDBmjKMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAkVT
MQwwCgYDVQQIDANNYWQxDzANBgNVBAcMBk1hZHJpZDEOMAwGA1UECgwFU2FudGEx
DTALBgNVBAsMBEJDT0UxDzANBgNVBAMMBlNBTkxBQjAeFw0yMjA1MTcxOTM3NTZa
Fw0yMzA1MTcxOTM3NTZaMGMxCzAJBgNVBAYTAkVTMQkwBwYDVQQIEwAxDzANBgNV
BAcTBk1hZHJpZDEVMBMGA1UECRMMU2FudGEgQ2FtcHVzMQ4wDAYDVQQREwUyODI2
NjERMA8GA1UEChMIU0FOVEFMQUIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7p8Pr14HYIAJMtkl2VkurNgaXVH/TnCA9CK9be57VLvWIaW46A0fYMYgB
xDEgohLd5mgK0JMk/eoYvSWFrK7iMJtJQSBpQ5wGvQ5ydE5LEi5tUZ4rdHpI8IFb
ZhoZ4gLJ0zcQAX1/4nBTAG7Rgt837LnRePMQDJxbN0AvQ3pqO2a9GtzLBRjwWlol
uIyn8G0Jv16LreCKz5Z8tG1sAUoklEK+zMQcbtevgkBhk+MOxjTB+ZzlSQr4YyX2
S+wENYItLWdIdPAm3/tIaIMnWfKBs/cx2F75rcjqQDWHxT9i4ldF2dilNrE89Bk5
9hZ4s0lteF1R6L2Jp9nKmK9kM2IPAgMBAAGjgYMwgYAwDgYDVR0PAQH/BAQDAgKE
MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBRVF65UGrEDojaG+MuQDoBZfYahhjAfBgNVHSMEGDAWgBQmuWhp
135LA4/A0CNqs0x8LHs5OjANBgkqhkiG9w0BAQsFAAOCAgEACQdZW3hT8C0hU26s
i3jZlrqise1sO0EptmmcAUO1TmSC14HP9LsySZYmAYU4c/4mNGg8s3rmazoTXEX9
I1d0SnVQ2rlid7OL9XEYEF0zU/FNGpryM6qsQyjeiQP82MyWRfRcwZVWqGH2G2H+
AiZsxeXGbPtW4SRKCTbEMq3En0Xh96UCvFZxZNFvR6ObAGfw7QO4OMhfG6xgcSK6
OsitJX5pdcovu4b46+ZCGq9ygiidIfEfX8ibylFlDXh/IQ7C17oLyC64I5lZ+39v
UooveEBDygLrSPTmNZWWHzYEMNhX2G0mZcBWPS9JRMguTI1dbHEysCciz8GmQs3C
Py5R0RLR6tKBPWpw34nMC79UF4hb8i0svOmi4pzPZdXvY5CYCbotIzu4BIIL2U2h
1hnv6tUEGLvXH7PT7aVgx6nbXaVs4xieUkIAi03fYyLeCHXe6lwnDn4x9M+dFS6O
iXgoqyZIW4C2jo1wDErXbAzd9iSRrAIZHfLLc5iq89VCEwp+oFMwiIySoyBo+2/1
fv/rUWDmsb6MtRNq7RB/svZjIexEONY5m1FxtbpUMY7zQxWVwLVyZB1c+vwFJAnj
06m1vP5XV7EGGAtJHytJ2B6jfjnHDenTlJkGNerfbUAZXumoPr6ZtpzVAzOr1cWl
ipKrCHwA9FxUFpwAf+sH+Iif1JA=
-----END CERTIFICATE-----`

const RSA4DILCertPem = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`
