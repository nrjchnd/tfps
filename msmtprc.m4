# Set default values for all following accounts.
defaults
port 587
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account SMTP_ACCOUNT
host SMTP_HOST
from SMTP_EMAIL
auth on
user SMTP_USER
password SMTP_PASSWORD

# Set a default account
account default : SMTP_ACCOUNT
