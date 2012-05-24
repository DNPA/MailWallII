#!/usr/bin/perl
require 5.006;
use strict;
package MessageIdFactory;
use Digest::MD5 qw(md5_base64);
use Moose;
use Proc::DaemonLite qw(:all);

has 'mLastMsgId' => (
   is  => 'rw',
   isa => 'Str',
);

sub newId {
   my $self = shift;
   unless ($self->mLastMsgId) {
     $self->mLastMsgId(time());
   }
   my $newmsgid=md5_base64($self->mLastMsgId);
   $newmsgid =~ s/\//_/g;
   $newmsgid .= time();
   $self->mLastMsgId($newmsgid);
   
   return $self->mLastMsgId;
}

no Moose;
__PACKAGE__->meta->make_immutable;
