#!/usr/bin/perl
require 5.006;
use strict;
package MailWallPeer;
use Moose;
use Proc::DaemonLite qw(:all);

has 'user' => (
   isa => 'Str',
   is => 'ro',
);

has 'domain' => (
   isa => 'Str',
   is => 'ro',
);

has 'rcptwhere' => (
   isa => 'Str',
   is => 'ro',
);

has 'owner' => (
   isa => 'Str',
   is => 'ro',
);

has 'id' => (
   isa => 'Int',
   reader => 'getId',
);

sub getAddress {
  my ($self) =@_;
  my $email = $self->user() . "\@" . $self->domain();
  return $email;
}

sub isLocal {
  my ($self) =@_;
  if ($self->rcptwhere() eq "local") {
    return 1;
  }
  return 0;
};

sub isRemote {
  my ($self) = @_;
  if ($self->rcptwhere() eq "remote") {
     return 1;
  }
  return 0;
};

sub isOk {
  my ($self) = @_;
  if (($self->rcptwhere() eq "local")||($self->rcptwhere() eq "remote")) {
     return 1;
  }
  return 0;
}

no Moose;
__PACKAGE__->meta->make_immutable;
