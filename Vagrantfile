# encoding: utf-8
# -*- mode: ruby -*-
# vi: set ft=ruby :
VAGRANT_BOX = 'bento/ubuntu-18.10'

VM_NAME = "deepstate"
GUEST_PATH = "/home/" + VM_NAME

# main configuration
Vagrant.configure(2) do |config|
  config.vm.box = VAGRANT_BOX
  config.vm.hostname = VM_NAME
  config.vm.provider "virtualbox" do |v|
    v.name = VM_NAME
    v.memory = 2048
    v.cpus = 4
  end

  config.vm.network "private_network", type: "dhcp"
  config.vm.synced_folder ".", GUEST_PATH

  # TODO: allow users to configure a dockerized vagrant build or a local one
  # configure scripts to run to provision environment
  config.vm.provision "shell", path: "./docker/deps", privileged: true
  config.vm.provision "shell", path: "./docker/install", privileged: false
end
