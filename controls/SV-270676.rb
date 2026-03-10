control 'SV-270676' do
  title 'Ubuntu 24.04 LTS must initiate session audits at system startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Verify Ubuntu 24.04 LTS enables auditing at system startup in GRUB. 

Check the main GRUB defaults to ensure that auditing is enabled:
$ sudo grep -ir GRUB_CMDLINE_LINUX /etc/default/grub
/etc/default/grub:GRUB_CMDLINE_LINUX_DEFAULT="audit=1"
/etc/default/grub:GRUB_CMDLINE_LINUX="audit=1"
 
If any linux lines do not contain "audit=1", this is a finding.

Check the generated GRUB configuration to ensure that the setting is propagated to the bootloader:
$ sudo grep "^\\s*linux" /boot/grub/grub.cfg 
linux   /vmlinuz-6.8.0-31-generic root=UUID=c92a542f-aee4-4af9-94b2-203624ccb8e3 ro audit=1 quiet splash $vt_handoff
linux   /vmlinuz-6.8.0-31-generic root=UUID=c92a542f-aee4-4af9-94b2-203624ccb8e3 ro recovery nomodeset dis_ucode_ldr audit=1
 
If any linux lines do not contain "audit=1", this is a finding.

Note: Output details may vary by system.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to produce audit records at system startup.  
 
Edit the "/etc/default/grub" file and add "audit=1" to the "GRUB_CMDLINE_LINUX" option and to the "GRUB_CMDLINE_LINUX_DEFAULT" option. 

GRUB_CMDLINE_LINUX_DEFAULT="audit=1"
GRUB_CMDLINE_LINUX="audit=1"
 
To update the grub config file, run: 
 
$ sudo update-grub'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000254-GPOS-00095']
  tag gid: 'V-270676'
  tag rid: 'SV-270676r1155245_rule'
  tag stig_id: 'UBTU-24-102010'
  tag fix_id: 'F-74610r1155231_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-001464', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'AU-14 (1)', 'MA-4 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  setting = /audit\s*=\s*1/
  default_grub = parse_config_file('/etc/default/grub')
  linux_cmdline = default_grub['GRUB_CMDLINE_LINUX']
  linux_default_cmdline = default_grub['GRUB_CMDLINE_LINUX_DEFAULT']
  grub_cfg_lines = command("grep -E '^\\s*linux' /boot/grub/grub.cfg").stdout

  describe 'GRUB defaults' do
    it 'should include audit=1 in GRUB_CMDLINE_LINUX and GRUB_CMDLINE_LINUX_DEFAULT' do
      expect(linux_cmdline).to match(setting), 'audit=1 not set in GRUB_CMDLINE_LINUX'
      expect(linux_default_cmdline).to match(setting), 'audit=1 not set in GRUB_CMDLINE_LINUX_DEFAULT'
    end
  end

  describe 'GRUB generated config' do
    it 'should include audit=1 on all kernel lines' do
      grub_cfg_lines.split("\n").each do |line|
        expect(line).to match(setting), 'audit=1 missing from a linux boot line'
      end
    end
  end
end
