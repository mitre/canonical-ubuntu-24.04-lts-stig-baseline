require 'openssl'
control 'SV-270745' do
  title 'Ubuntu 24.04 LTS must use DOD PKI-established certificate authorities (CAs) for verification of the establishment of protected sessions.'
  desc 'Untrusted CAs can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

The DOD will only accept PKI-certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.'
  desc 'check', 'Verify the directory containing the root certificates for Ubuntu 24.04 LTS contains certificate files for DOD PKI-established CAs by iterating over all files in the "/etc/ssl/certs" directory and checking if, at least one, has the subject matching "DOD ROOT CA".

$ grep -ir DOD /etc/ssl/certs
DOD_PKE_CA_chain.pem

If no root certificate is found, this is a finding.'
  desc 'fix', %q(Configure Ubuntu 24.04 LTS to use of DOD PKI-established CAs for verification of the establishment of protected sessions.

Edit the "/etc/ca-certificates.conf" file, adding the character "!" to the beginning of all uncommented lines that do not start with the "!" character with the following command:

$ sudo sed -i -E 's/^([^!#]+)/!\1/' /etc/ca-certificates.conf

Add at least one CA to the "/usr/local/share/ca-certificates" directory in the PEM format.

Update the "/etc/ssl/certs" directory with the following command:

$ sudo update-ca-certificates)
  impact 0.5
  tag check_id: 'C-74778r1066722_chk'
  tag severity: 'medium'
  tag gid: 'V-270745'
  tag rid: 'SV-270745r1066724_rule'
  tag stig_id: 'UBTU-24-600060'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-74679r1066723_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
  tag 'host'
  tag 'container'

  approved_fingerprints = input('allowed_ca_fingerprints_regex')
                          .scan(/[0-9a-f]{64}/i)
                          .map(&:upcase)
                          .uniq

  trusted_ca_bundle = file('/etc/ssl/certs/ca-certificates.crt')

  describe 'The system trusted CA bundle' do
    it 'contains at least one certificate with an approved DoD CA SHA-256 fingerprint' do
      inspection_error = nil
      installed_fingerprints = []

      begin
        certificates = trusted_ca_bundle.content.to_s.scan(
          /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m
        )

        installed_fingerprints = certificates.map do |pem|
          certificate = OpenSSL::X509::Certificate.new(pem)
          OpenSSL::Digest::SHA256.hexdigest(certificate.to_der).upcase
        end
      rescue StandardError => e
        inspection_error = "#{e.class}: #{e.message}"
      end

      expect(approved_fingerprints).not_to be_empty,
        "input('allowed_ca_fingerprints_regex') contains no valid SHA-256 fingerprints"

      expect(inspection_error).to be_nil,
        "Unable to inspect /etc/ssl/certs/ca-certificates.crt: #{inspection_error}"

      expect(installed_fingerprints & approved_fingerprints).not_to be_empty,
        'No certificate in /etc/ssl/certs/ca-certificates.crt has an approved DoD CA SHA-256 fingerprint'
    end
  end
end
