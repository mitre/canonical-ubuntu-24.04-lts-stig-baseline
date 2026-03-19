control 'SV-270668' do
  title 'Ubuntu 24.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes.'
  desc 'check', 'Verify the SSH daemon is configured to only use MACs that employ FIPS 140-3 approved ciphers with the following command:

$ grep -irs macs /etc/ssh/sshd_config*
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If any algorithms other than "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" are listed, the returned line is commented out, or if conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to allow the SSH daemon to only use MACs that employ FIPS 140-3 approved ciphers.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

Restart the "sshd" service for changes to take effect:

$ sudo systemctl restart sshd'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000424-GPOS-00188']
  tag gid: 'V-270668'
  tag rid: 'SV-270668r1067110_rule'
  tag stig_id: 'UBTU-24-100830'
  tag fix_id: 'F-74602r1067109_fix'
  tag cci: ['CCI-001453', 'CCI-002421', 'CCI-002890']
  tag nist: ['AC-17 (2)', 'SC-8 (1)', 'MA-4 (6)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable - SSH is not installed within containerized Ubuntu', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
  }

  approved_macs = input('approved_openssh_server_conf')['macs']

  macs_cmd = command("/usr/sbin/sshd -T 2>/dev/null | awk '$1==\"macs\"{print $2}'")
  actual_macs = macs_cmd.stdout.strip

  describe 'OpenSSH server MACs' do
    it 'matches the approved list in exact order' do
      expect(actual_macs).to eq(approved_macs), "OpenSSH server MACs:\n\t#{actual_macs}\ndoes not match the expected value:\n\t#{approved_macs}"
    end
  end
end
