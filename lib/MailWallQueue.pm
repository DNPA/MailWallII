#!/usr/bin/perl
require 5.006;
use strict;
use MessageIdFactory;
use MailWallMessage;
use MailWallDb;
package MailWallQueue;
use Moose;
use Proc::DaemonLite qw(:all);

has 'spoolpath' => (
   is  => 'rw',
   isa => 'Str',
);

has 'db' => (
   is => 'ro',
   isa => 'MailWallDb',
);

has 'domain' => (
   is => 'ro',
   isa => 'Str',
);

has 'msgidfactory' => (
   is => 'ro',
   isa => 'MessageIdFactory',
   default => sub { return new MessageIdFactory();},
);

sub newMessage {
  my ($self,$data,$sender,$client) = @_;
  my $queuedir=$self->spoolpath() . "/" . $client->getIp();
  my $msgidfactory=$self->msgidfactory();
  my $msgid=$msgidfactory->newId();
  my $queuefile = $queuedir . "/" . $msgid;
  mkdir($queuedir);
  open(OUT,">$queuefile") || die "Unable to create queue file $queuefile\n";
  print OUT $$data;  
  close(OUT);
  my $db=$self->db();
  unless ($db) {
    log_die("MailWallQueue with no db, this should not happen");
  }
  my $domain= "mailwall." . $self->domain();
  my $fullmsgid = $msgid . "\@" . $domain;
  return new MailWallMessage(file => $queuefile,id => $fullmsgid, db => $db);
};

no Moose;
__PACKAGE__->meta->make_immutable;
