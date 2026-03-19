control 'SV-270825' do
  title 'Ubuntu 24.04 LTS must have directories that contain system commands owned by root.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has to make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', %q(Verify the system commands directories are owned by root with the following command:

$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;

If any system commands directories are returned, this is a finding.)
  desc 'fix', "Configure the system commands directories to be protected from unauthorized access. Run the following command:

$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec chown root '{}' \\;"
  impact 0.5
  tag check_id: 'C-74858r1066962_chk'
  tag severity: 'medium'
  tag gid: 'V-270825'
  tag rid: 'SV-270825r1066964_rule'
  tag stig_id: 'UBTU-24-901270'
  tag gtitle: 'SRG-OS-000258-GPOS-00099'
  tag fix_id: 'F-74759r1066963_fix'
  tag 'documentable'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
  tag 'host'
  tag 'container'

  system_commands = command('find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d').stdout.strip.split("\n").entries
  valid_system_commands = Set[]

  if system_commands.any?
    system_commands.each do |sys_cmd|
      valid_system_commands << sys_cmd if file(sys_cmd).exist?
    end
  end

  if valid_system_commands.any?
    valid_system_commands.each do |val_sys_cmd|
      describe file(val_sys_cmd) do
        its('owner') { should cmp 'root' }
      end
    end
  else
    describe "Number of directories that contain system commands found in /bin, /sbin, /usr/bin, /usr/sbin,
      /usr/local/bin or /usr/local/sbin, that are NOT owned by root" do
        subject { valid_system_commands }
        its('count') { should eq 0 }
      end
  end
end
