control 'SV-270665' do
  title 'Ubuntu 24.04 LTS must have SSH installed.'
  desc 'Without protection of the transmitted information, confidentiality and
integrity may be compromised because unprotected communications can be
intercepted and either read or altered.

    This requirement applies to both internal and external networks and all
types of information system components from which information can be
transmitted (e.g., servers, mobile devices, notebook computers, printers,
copiers, scanners, and facsimile machines). Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of
interception and modification.

    Protecting the confidentiality and integrity of organizational information
can be accomplished by physical means (e.g., employing physical distribution
systems) or by logical means (e.g., employing cryptographic techniques). If
physical means of protection are employed, then logical means (cryptography) do
not have to be employed, and vice versa.'
  desc 'check', 'Verify the SSH package is installed with the following command:

$ dpkg -l | grep openssh
ii  openssh-client     1:9.6p1-3ubuntu13.5     amd64     secure shell (SSH) client, for secure access to remote machines
ii  openssh-server     1:9.6p1-3ubuntu13.5     amd64     secure shell (SSH) server, for secure access from remote machines
ii  openssh-sftp-server     1:9.6p1-3ubuntu13.5     amd64     secure shell (SSH) sftp server module, for SFTP access from remote machines

If the "openssh" server package is not installed, this is a finding.'
  desc 'fix', 'Install the "ssh" meta-package on the system with the following command:

$ sudo apt install -y ssh'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag gid: 'V-270665'
  tag rid: 'SV-270665r1067133_rule'
  tag stig_id: 'UBTU-24-100800'
  tag fix_id: 'F-74599r1067132_fix'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)']
  tag 'host'
  tag 'container-conditional'

  openssh_present = package('openssh-server').installed?
  is_container = %w[docker podman kubepods lxc].include?(virtualization.system)
  allow_container_openssh = input('allow_container_openssh_server')

  only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
    !(is_container && !openssh_present)
  }

  if is_container
    describe 'In a container Environment' do
      it 'the OpenSSH Server should be installed only when allowed in a container environment' do
        expect(openssh_present).to eq(allow_container_openssh), 'OpenSSH Server is installed but not approved for the container environment'
      end
    end
  else
    describe 'In a machine environment' do
      it 'the OpenSSH Server should be installed' do
        expect(openssh_present).to eq(true), 'the OpenSSH Server is not installed'
      end
    end
  end
end
