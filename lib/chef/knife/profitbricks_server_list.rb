# encoding: UTF-8

require 'chef/knife'
require 'chef/json_compat'
require 'pp'

require_relative 'profitbricks_base'
class Chef
  class Knife
    class ProfitbricksServerList < Knife
      require_relative 'profitbricks_base'
      deps do
        require 'profitbricks'
        require 'highline'

        Chef::Knife.load_deps
      end

      include Chef::Knife::ProfitbricksBase

      banner "knife profitbricks server list OPTIONS"

      option :datacenter_name,
        :short => "-D DATACENTER_NAME",
        :long => "--data-center DATACENTER_NAME",
        :description => "The datacenter where the server will be created",
        :proc => Proc.new { |datacenter| Chef::Config[:knife][:profitbricks_datacenter] = datacenter }

      def h
        @highline ||= HighLine.new
      end

      def run
        validate!
        configure

        unless Chef::Config[:knife][:profitbricks_datacenter]
          ui.error("A Datacenter must be specified, please run ==knife profitbricks server list -D<DATACENTER> --help== for more information")
          exit 1
        end

        #datacenters = Profitbricks::DataCenter.all

        ui.info "Going to search of all servers in: "
        msg_pair("Datacenter", Chef::Config[:knife][:profitbricks_datacenter])

        puts "#{ui.color("Locating Datacenter ", :magenta)}"
        @dc = DataCenter.find(:name => Chef::Config[:knife][:profitbricks_datacenter])
        puts "#{ui.color("found dataCenter with Id : #{@dc.id} and Name: #{@dc.name}", :magenta)}"

        #pp @dc.servers

        server_list = [
            #ui.color('ServerID', :bold),
            ui.color('Name', :bold),
            ui.color('VM_State', :bold),
            ui.color('CPUs', :bold),
            ui.color('RAM', :bold),
            ui.color('Lan_ID', :bold),
            ui.color('internet', :bold),
            ui.color('IPs', :bold),
            ui.color('MAC', :bold),
            ui.color('DHCP', :bold),
            ui.color('HDD-Size', :bold)
            #ui.color('HD_DeviceNr', :bold)
        ]

          @dc.servers.each do |s|
            s.nics.each do |n|
              s.connected_storages.each do |hd|
                #server_list << s.id
                server_list << s.name
                server_list << s.virtual_machine_state
                server_list << s.cores.to_s
                server_list << s.ram.to_s
                server_list << n.lan_id.to_s
                server_list << n.internet_access.to_s
                server_list << n.ips.first
                #server_list << (n.respond_to?("ips") ? s.ips.to_s : "")
                server_list << n.mac_address
                server_list << n.dhcp_active.to_s
                server_list << hd.size.to_s
                #server_list << hd.device_number.to_s
              end
            end
          end

        puts ui.list(server_list, :uneven_columns_across, 10)
      end
    end
  end
end
