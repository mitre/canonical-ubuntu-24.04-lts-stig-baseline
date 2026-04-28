control 'SV-270670' do
  title 'Ubuntu 24.04 LTS must configure the SSH client to use FIPS 140-3 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes.

By specifying a cipher list with the order of ciphers being in a "strongest to weakest" orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.'
  desc 'check', %q(Verify the SSH client is configured to use only ciphers employing FIPS 140-3 approved algorithms with the following command:

$ sudo grep -r 'Ciphers' /etc/ssh/ssh_config*
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr

If any ciphers other than "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr" are listed, the "Ciphers" keyword is missing, or the returned line is commented out, or if multiple conflicting ciphers are returned, this is a finding.)
  desc 'fix', 'Configure the Ubuntu 24.04 LTS SSH client to use only ciphers employing FIPS 140-3 approved algorithms by updating the "/etc/ssh/ssh_config" file with the following line:

Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr

Restart the "ssh" service for changes to take effect:

$ sudo systemctl restart ssh'
  impact 0.5
  tag check_id: 'C-74703r1067113_chk'
  tag severity: 'medium'
  tag gid: 'V-270670'
  tag rid: 'SV-270670r1067115_rule'
  tag stig_id: 'UBTU-24-100850'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-74604r1067114_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'

  if input('disable_fips')
    impact 0.0
    describe 'FIPS testing has been disabled' do
      skip 'This control has been set to Not Applicable, FIPS validation has been disabled with the `disable_fips` input'
    end
  elsif %w[docker podman kubepods lxc].include?(virtualization.system)
    describe 'FIPS validation in a container must be reviewed manually' do
      skip 'FIPS validation in a container must be reviewed manually'
    end
  else
    approved = %w[aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes128-ctr]
    ciphers = inspec.sshd_config.params['ciphers']
    ciphers = ciphers.first.split(',').map(&:strip) unless ciphers.nil?

    describe 'SSH ciphers' do
      it 'should contain only approved FIPS ciphers' do
        unapproved_ciphers = ciphers.nil? ? [] : (ciphers - approved)
        missing_approved_ciphers = ciphers.nil? ? approved : (approved - ciphers)

        expect(ciphers).to_not be_nil, 'Ciphers directive missing from sshd_config'
        expect(unapproved_ciphers).to eq([]), "Non-approved ciphers present (#{unapproved_ciphers.length}): #{unapproved_ciphers.join(', ')}"
        expect(missing_approved_ciphers).to eq([]), "Approved ciphers missing (#{missing_approved_ciphers.length}): #{missing_approved_ciphers.join(', ')}"
      end
    end
  end
end
