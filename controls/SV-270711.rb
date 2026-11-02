control 'SV-270711' do
  title 'Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify Ubuntu 24.04 LTS is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface with the following command:

$ gsettings get org.gnome.settings-daemon.plugins.media-keys logout
@as []

If the "logout" key is bound to an action, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to disable the Ctrl-Alt-Delete sequence when using a graphical user interface.

Create or edit a file named /etc/dconf/db/local.d/00-mediakeys with the following contents:

[org/gnome/settings-daemon/plugins/media-keys]
logout=@as []

Update the dconf settings:

$ sudo dconf update'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-270711'
  tag rid: 'SV-270711r1268251_rule'
  tag stig_id: 'UBTU-24-300025'
  tag fix_id: 'F-74645r1184068_fix'
  tag cci: ['CCI-000366', 'CCI-002235']
  tag nist: ['CM-6 b', 'AC-6 (10)']
  tag 'host'

  xorg_status = command('which Xorg').exit_status
  if xorg_status == 0
    # V1R7 expects `logout=@as []`; the older `logout=''` / `logout=['']` forms also unbind the key
    logout_settings = command("grep -REh '^\\s*logout\\s*=' /etc/dconf/db/local.d/").stdout.strip.split("\n")
    describe 'The GNOME media-keys logout binding in /etc/dconf/db/local.d/' do
      it 'should be set to an empty value' do
        expect(logout_settings).not_to be_empty, 'No uncommented `logout=` setting found'
        expect(logout_settings).to all(match(/^\s*logout\s*=\s*(@as\s*\[\s*\]|\[\s*''\s*\]|'')\s*$/))
      end
    end
  else
    impact 0.0
    describe command('which Xorg').exit_status do
      skip('This control is Not Applicable since a GUI not installed.')
    end
  end
end
