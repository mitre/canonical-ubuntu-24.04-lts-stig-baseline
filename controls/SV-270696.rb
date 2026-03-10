control 'SV-270696' do
  title 'Ubuntu 24.04 LTS library files must have mode 0755 or less permissive.'
  desc 'If Ubuntu 24.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" have mode 0755 or less permissive.

Check that the systemwide shared library files have mode 0755 or less permissive with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec stat -c "%n %a" {} +

If any output is returned, this is a finding.)
  desc 'fix', %q(Configure the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" to have mode 0755 or less permissive with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec chmod go-w {} +)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-270696'
  tag rid: 'SV-270696r1107306_rule'
  tag stig_id: 'UBTU-24-300006'
  tag fix_id: 'F-74630r1107305_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  failing_files = command("find -L #{input('system_libraries').join(' ')} -type f -name '*.so*' -perm /0022 -exec ls -d {} \\;").stdout.split("\n")

  describe 'System libraries' do
    it "should have mode '0755' or less permissive" do
      expect(failing_files).to be_empty, "Files with excessive permissions:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
