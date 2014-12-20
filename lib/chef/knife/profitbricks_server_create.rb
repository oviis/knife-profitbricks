require 'chef/knife'
require 'chef/json_compat'
require_relative 'profitbricks_base'

class Chef
  class Knife
    class ProfitbricksServerCreate < Knife

      deps do
        require 'net/ssh'
        require 'net/ssh/multi'
        require 'profitbricks'
        require 'highline'
        require 'chef/knife/bootstrap'
        require 'chef/knife/core/bootstrap_context'
        require 'securerandom'
        require 'timeout'
        require 'socket'

        Chef::Knife.load_deps

      end
      include Knife::ProfitbricksBase


      banner "knife profitbricks server create OPTIONS"

      option :datacenter_name,
        :short => "-D DATACENTER_NAME",
        :long => "--data-center DATACENTER_NAME",
        :description => "The datacenter where the server will be created",
        :proc => Proc.new { |datacenter| Chef::Config[:knife][:profitbricks_datacenter] = datacenter }

      option :name,
        :long => "--name SERVER_NAME",
        :description => "name for the newly created Server",
        :proc => Proc.new { |image| Chef::Config[:knife][:profitbricks_server_name] = image }

      option :memory,
        :long => "--ram RAM",
        :description => "Amount of Memory in MB of the new Server",
        :proc => Proc.new { |memory| Chef::Config[:knife][:profitbricks_memory] = memory }

      option :cpus,
        :long => "--cpus CPUS",
        :description => "Amount of CPUs of the new Server",
        :proc => Proc.new { |cpus| Chef::Config[:knife][:profitbricks_cpus] = cpus }

      option :lan_id,
        :short => "-L LAN_ID",
        :long => "--lan_id LAN_ID",
        :description => "This is the Profitbricks LAN_ID if you have more than one LAN",
        :proc => Proc.new { |lan_id| Chef::Config[:knife][:profitbricks_lan_id] = lan_id }

      option :wan_id,
        :short => "-W WAN_ID",
        :long => "--wan_id WAN_ID",
        :description => "This is the Profitbricks WAN_ID for accesing the internet",
        :proc => Proc.new { |wan_id| Chef::Config[:knife][:profitbricks_wan_id] = wan_id }

      option :private_ip,
        :short => "-IP PRIVATE_IP",
        :long => "--private_ip PRIVATE_IP",
        :description => "Private IPS must be in LANs 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16",
        :proc => Proc.new { |private_ip| Chef::Config[:knife][:profitbricks_private_ip] = private_ip }

      option :hdd_size,
        :long => "--hdd-size GB",
        :description => "Size of storage in GB, if activate, will be create the HDD additionaly",
        :default => "25"

      option :dhcpActive,
        :long => "--dhcpActive true/false",
        :description => "Profitbricks DHCP Server activate",
        :default => false

      option :activate_gateway_ip,
        :short => "-G GATEWAY_IP",
        :long => "--activate-gateway IP",
        :description => "Profitbricks DHCP Server activate as a IP Adress"

      option :bootstrap,
        :long => "--[no-]bootstrap",
        :description => "Bootstrap the server with knife bootstrap",
        :boolean => true,
        :default => true

      option :ssh_user,
        :short => "-x USERNAME",
        :long => "--ssh-user USERNAME",
        :description => "The user to create and add the provided public key to authorized_keys, default is 'root'",
        :default => "root"

      option :identity_file,
        :short => "-iF IDENTITY_FILE",
        :long => "--identity-file IDENTITY_FILE",
        :description => "The SSH identity file used for authentication",
        :default => "#{File.expand_path('~')}/.ssh/id_rsa"

      option :image_name,
        :short => "-I IMAGE_NAME",
        :long => "--image-name IMAGE_NAME",
        :description => "The image name which will be used to create the server, default is 'Ubuntu-12.04-LTS-server-amd64-06.21.13.img'",
        :default => 'Ubuntu-12.04-LTS-server-amd64-06.21.13.img'

      option :location_name,
        :short => "-loc LOCATION_NAME",
        :long => "--location-name LOCATION_NAME",
        :description => "The Location of the datacenters, default is Karlsruhe 'de/fkb' ",
        :default => 'de/fkb'

      option :snapshot_name,
        :short => '-S SNAPSHOT_NAME',
        :long => "--snaphot-name SNAPSHOT_NAME",
        :description => "The snapshot name which will be used to create the server (can not be used with the image-name option)",
        :proc => Proc.new { |s| Chef::Config[:knife][:profitbricks_snapshot_name] = s }

      option :public_key_file,
        :short => "-k PUBLIC_KEY_FILE",
        :long => "--public-key-file PUBLIC_KEY_FILE",
        :description => "The SSH public key file to be added to the authorized_keys of the given user, default is '~/.ssh/id_rsa.pub'",
        :default => "#{File.expand_path('~')}/.ssh/id_rsa.pub"

      option :run_list,
        :short => "-r RUN_LIST",
        :long => "--run-list RUN_LIST",
        :description => "Comma separated list of roles/recipes to apply",
        :proc => lambda { |o| o.split(/[\s,]+/) },
        :default => []

      option :distro,
        :short => "-d DISTRO",
        :long => "--distro DISTRO",
        :description => "Bootstrap a distro using a template; default is 'ubuntu12.04-gems'",
        :proc => Proc.new { |d| Chef::Config[:knife][:distro] = d },
        :default => "ubuntu12.04-gems"

      option :template_file,
        :long => "--template-file TEMPLATE",
        :description => "Full path to location of template to use",
        :proc => Proc.new { |t| Chef::Config[:knife][:template_file] = t },
        :default => false

      option :chef_node_name,
        :short => "-N NAME",
        :long => "--node-name NAME",
        :description => "The Chef node name for your new node default is the name of the server.",
        :proc => Proc.new { |t| Chef::Config[:knife][:chef_node_name] = t }

      option :ssh_password,
       :short => "-P PASSWORD",
       :long => "--ssh-password PASSWORD",
       :description => "The ssh password to use, default is a random generated one.",
       :proc => Proc.new { |password| Chef::Config[:knife][:ssh_password] = password }


      def h
        @highline ||= HighLine.new
      end

      def run
        validate!
        configure

        unless Chef::Config[:knife][:profitbricks_datacenter]
          ui.error("A Datacenter must be specified")
          exit 1
        end

        unless Chef::Config[:knife][:profitbricks_lan_id]
          ui.error("A LAN_ID must be specified, to bring the server in a network")
          exit 1
        end

        unless Chef::Config[:knife][:profitbricks_wan_id]
          ui.error("A WAN_ID must be specified, to give the server acces to internet for configuring!")
          exit 1
        end

        unless Chef::Config[:knife][:profitbricks_server_name]
          ui.error("You need to provide a name for the server")
          exit 1
        end

        ui.info "Going to create a new server"
        msg_pair("Name", Chef::Config[:knife][:profitbricks_server_name])
        msg_pair("Datacenter", Chef::Config[:knife][:profitbricks_datacenter])
        msg_pair("Image", Chef::Config[:knife][:profitbricks_image])
        msg_pair("LAN_ID", Chef::Config[:knife][:profitbricks_lan_id])
        msg_pair("WAN_ID", Chef::Config[:knife][:profitbricks_wan_id])
        msg_pair("Gateway_IP", locate_config_value(:activate_gateway_ip))
        msg_pair("Private_IP", Chef::Config[:knife][:profitbricks_private_ip])
        msg_pair("CPUs", Chef::Config[:knife][:profitbricks_cpus] || 1)
        msg_pair("Memory", Chef::Config[:knife][:profitbricks_memory] || 1024)

        puts "#{ui.color("Locating Datacenter ", :magenta)}"
        @dc = DataCenter.find(:name => Chef::Config[:knife][:profitbricks_datacenter])
        puts "#{ui.color("found dataCenter with Id : #{@dc.id} and Name: #{@dc.name}", :magenta)}"
        @dc.wait_for_provisioning

        # DELETEME for debugging only
        #@dc.clear
        #@dc.wait_for_provisioning
        # DELETEME

        create_server()

        #@password = @new_password
        #change_password()
        #puts ui.color("Changed the password successfully", :green)
        
        #if config[:activate_gateway_ip]
        # activate_gateway()
        #end

        #upload_ssh_key

        if config[:bootstrap]
          bootstrap()
        end

        msg_pair("ID", @server.id)
        msg_pair("Name", @server.name)
        msg_pair("Datacenter", @dc.name)
        msg_pair("CPUs", @server.cores.to_s)
        msg_pair("RAM", @server.ram.to_s)
      end

      def create_server
        @password = SecureRandom.hex.gsub(/[i|l|0|1|I|L]/,'')
        #@new_password = SecureRandom.hex.gsub(/[i|l|0|1|I|L]/,'')
        @hdd_name = SecureRandom.hex(4)

        #locating given image or snapshot
        if locate_config_value(:profitbricks_snapshot_name)
          puts "#{ui.color("Locating Snapshot", :magenta)}"
          @snapshot = Snapshot.find(:name => locate_config_value(:profitbricks_snapshot_name))
        else
          puts "#{ui.color("Locating Image", :magenta)}"  
          @image = Image.find(:name => locate_config_value(:image_name), :location => locate_config_value(:location_name))
          puts "#{ui.color("found Image with Id : #{@image.id} and Name: #{@image.name}", :magenta)}"
        end

   

          if locate_config_value(:profitbricks_snapshot_name)
            wait_for(ui.color("Creating Storage", :magenta)) { @dc.provisioned? }
            @hdd1 = Storage.create(
                             :size => locate_config_value(:hdd_size),
                             :data_center_id => @dc.id,
                             :name => "HDD-#{@hdd_name}",
                             :bus_type => 'VIRTIO'
                             )
            @snapshot.update(:bootable => true)
            @snapshot.rollback(:storage_id => @hdd1.id)
            wait_for("#{ui.color("Applying Snapshot", :magenta)}") { @dc.provisioned? }
          elsif locate_config_value(:image_name)
            puts "#{ui.color("will merge HDD with ImageId : #{@image.id} and ImageName: #{@image.name}", :magenta)}"
            wait_for(ui.color("Creating Storage", :magenta)) { @dc.provisioned? }
            @hdd1 = Storage.create(:mount_image_id => @image.id,
                                   :profit_bricks_image_password => @password,
                                   :size => locate_config_value(:hdd_size),
                                   :data_center_id => @dc.id,
                                   :name => "HDD-#{@hdd_name}"
                                )
          end


        if locate_config_value(:profitbricks_snapshot_name)
          puts "#{ui.color("Start to create the Server and booting from #{@hdd1.name} ", :magenta)}"
          @server = @dc.create_server(:cores => Chef::Config[:knife][:profitbricks_cpus] || 1,
                                  :ram => Chef::Config[:knife][:profitbricks_memory] || 1024,
                                  :name => Chef::Config[:knife][:profitbricks_server_name] || "ServerNoName",
                                  :boot_from_storage_id => @hdd1.id
                                  )
        else
          puts "#{ui.color("Start to create the Server and booting from #{@hdd1.name} ", :magenta)}"
          @server = @dc.create_server(:cores => Chef::Config[:knife][:profitbricks_cpus] || 1,
                                  :ram => Chef::Config[:knife][:profitbricks_memory] || 1024,
                                  :name => Chef::Config[:knife][:profitbricks_server_name] || "ServerNoName",
                                  :boot_from_storage_id => @hdd1.id
                                  )
        end
        @dc.wait_for_provisioning
        wait_for(ui.color("Waiting for the Server to be created", :magenta)) { @dc.provisioned? }

        @lan_id_number = Chef::Config[:knife][:profitbricks_lan_id]
        @wan_id_numer = Chef::Config[:knife][:profitbricks_wan_id]

        @nic_private = @server.create_nic(:lan_id => @lan_id_number, 
                       :dhcpActive => locate_config_value(:dhcpActive),
                       :name => "GREEN",
                       :server_id => @server.id,
                       :ip => Chef::Config[:knife][:profitbricks_private_ip])

        @nic_public = @server.create_nic( 
                       :lan_id => @wan_id_numer,
                       :dhcpActive => "true",
                       :name => "RED",
                       :server_id => @server.id)

        @nic_public.set_internet_access=(true)

        @dc.wait_for_provisioning

        wait_for(ui.color("Waiting for the Server to be accessible", :magenta)) { ssh_test(@server.public_ips.first) }

        if locate_config_value(:ssh_password)
          puts "#{ui.color("given password will be applied", :magenta)}"
          @new_password = Chef::Config[:knife][:ssh_password]
          @password = @new_password
          change_password()
        end

        wait_for(ui.color("Server with Name #{@server.name} and ServerId: #{@server.id} with NIC-IP #{@nic_private.ip} and lan_id #{@lan_id_number} created", :green)) { @dc.provisioned? }
        wait_for(ui.color("Done creating new Server and booting from HDD.Id #{@hdd1.id}", :green)) {@server.provisioned?}

        #@server.start
        wait_for(ui.color("Waiting for the Server to boot", :magenta)) { @server.running? }

        @server = Server.find(:id => @server.id)
      end

      def ssh_test(ip)
        begin
          timeout 2 do
            s = TCPSocket.new ip, 22
            s.close
            true
          end
        rescue Timeout::Error, Errno::ECONNREFUSED
          false
        end
      end

      def upload_ssh_key
        ## SSH Key
        ssh_key = begin
          File.open(locate_config_value(:public_key_file)).read.gsub(/\n/,'')
        rescue Exception => e
          ui.error(e.message)
          ui.error("Could not read the provided public ssh key, check the public_key_file config.")
          exit 1
        end

        dot_ssh_path = if locate_config_value(:ssh_user) != 'root'
          ssh("useradd #{locate_config_value(:ssh_user)} -G sudo -m").run
          "/home/#{locate_config_value(:ssh_user)}/.ssh"
        else
          "/root/.ssh"
        end
        ssh("mkdir -p #{dot_ssh_path} && echo \"#{ssh_key}\" > #{dot_ssh_path}/authorized_keys && chmod -R go-rwx #{dot_ssh_path}").run
        puts ui.color("Added the ssh key to the authorized_keys of #{locate_config_value(:ssh_user)}", :green)
      end

      def activate_gateway
        ssh("route add default gw #{locate_config_value(:activate_gateway_ip)}").run
        puts ui.color("added the gateway route for gateway Server with IP #{locate_config_value(:activate_gateway_ip)}", :green)
      end

      def change_password
        ui.color("start to change the password", :green)
        Net::SSH.start( @server.public_ips.first, 'root', :password =>@password, :paranoid => false ) do |ssh|
          ssh.open_channel do |channel|
             channel.on_request "exit-status" do |channel, data|
                $exit_status = data.read_long
             end
             channel.on_data do |channel, data|
                if data.inspect.include? "current"
                        channel.send_data("#{@password}\n");
                elsif data.inspect.include? "New"
                        channel.send_data("#{@new_password}\n");
                elsif data.inspect.include? "new"
                        channel.send_data("#{@new_password}\n");
                end
             end
             channel.request_pty
             channel.exec("passwd");
             channel.wait

             return $exit_status == 0
          ui.color("password changed successfully", :green)
          end
        end
      end

      def bootstrap
        bootstrap = Chef::Knife::Bootstrap.new
        bootstrap.name_args = @server.ips
        bootstrap.config[:run_list] = locate_config_value(:run_list)
        bootstrap.config[:ssh_user] = locate_config_value(:ssh_user)
        bootstrap.config[:ssh_password] = @password
        bootstrap.config[:host_key_verify] = false
        bootstrap.config[:chef_node_name] = locate_config_value(:chef_node_name) || @server.name
        bootstrap.config[:distro] = locate_config_value(:distro)
        bootstrap.config[:use_sudo] = true unless bootstrap.config[:ssh_user] == 'root'
        bootstrap.config[:template_file] = locate_config_value(:template_file)
        bootstrap.run
        # This is a temporary fix until ohai 6.18.0 is released
        ssh("gem install ohai --pre --no-ri --no-rdoc && chef-client").run
      end
    end
  end
end
