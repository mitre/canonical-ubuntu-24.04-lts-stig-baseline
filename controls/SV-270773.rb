control 'SV-270773' do
  title 'Ubuntu 24.04 LTS must be configured so that Advance Package Tool (APT) removes all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Verify APT is configured to remove all software components after updated versions have been installed with the following command: 
 
$ grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades 
Unattended-Upgrade::Remove-Unused-Dependencies "true"; 
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true"; 
 
If the "::Remove-Unused-Dependencies" and "::Remove-Unused-Kernel-Packages" parameters are not set to "true", are commented out, or are missing, this is a finding.'
  desc 'fix', 'Configure APT to remove all software components after updated versions have been installed. 
 
Add or update the following options to the "/etc/apt/apt.conf.d/50unattended-upgrades" file: 
 
Unattended-Upgrade::Remove-Unused-Dependencies "true"; 
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";'
  impact 0.5
  tag check_id: 'C-74806r1066806_chk'
  tag severity: 'medium'
  tag gid: 'V-270773'
  tag rid: 'SV-270773r1066808_rule'
  tag stig_id: 'UBTU-24-700320'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-74707r1066807_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
  tag 'host'
  tag 'container'

  describe directory('/etc/apt/apt.conf.d') do
    it { should exist }
  end

  describe command('grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades').stdout.strip do
    it { should match(/^\s*Unattended-Upgrade::Remove-Unused-Dependencies\s*"true"\s*;$/) }
    it { should match(/^\s*Unattended-Upgrade::Remove-Unused-Kernel-Packages\s*"true"\s*;$/) }
  end
end
