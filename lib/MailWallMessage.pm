#!/usr/bin/perl
require 5.006;
use strict;
use MailWallDb;
package MailWallMessage;
use Moose;
use Proc::DaemonLite qw(:all);

has 'file' => (
   isa => 'Str',
   is => 'ro',
);

has 'id' => (
   isa => 'Str',
   is => 'ro',
);

has 'db' => (
   isa => 'MailWallDb',
   is => 'ro',
);

sub getMsgId {
  my ($self) =@_;
  return $self->id();
}

sub hasBinary {
  my ($self) =@_;
  my $path=$self->file();
  unless (open(DATA,$path)) { 
     log_warn("Unable to open : '$path' from MailWallMessage, this should not happen.");
     return 1;
  }
  while (<DATA>) {
    if ((/^begin\s\d+\s\S+/i)||(/\s(application\/\w+)/)||(/\smessage\/external-body/)||(/\smessage\/partial/)) {
       close(DATA);
       return 1;
    }
  }
  close(DATA);
  return 0;
};


sub addToQueue {
  my ($self,$queue,$recipient,$clientid,$senderid) =@_;
  my $db=$self->db();
  my $id=$self->id();
  my $file = $self->file();
  $db->addToQueue($id,$file,$recipient->getAddress(),$queue,$clientid,$senderid);
  log_notice("Added message " . $id . " to the " . $queue . " queue for " . $recipient->getAddress());
  return;
}

no Moose;
__PACKAGE__->meta->make_immutable;
