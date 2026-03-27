use strict;
use warnings;
use ExtUtils::MakeMaker;

my $dist = {
	COMPRESS => 'gzip -9f',	# Compress tarball using gzip
	SUFFIX => 'gz',	# File suffix for tarball
};

if($^O eq 'darwin') {
	$dist->{'TAR'} = 'gtar';
}

WriteMakefile(
	NAME		=> 'Mail::Message::Abuse',
	AUTHOR		=> q{Nigel Horne <njh@nigelhorne.com>},
	VERSION_FROM	=> 'lib/Mail/Message/Abuse.pm',
	ABSTRACT_FROM	=> 'lib/Mail/Message/Abuse.pm',
	((defined($ExtUtils::MakeMaker::VERSION) && ($ExtUtils::MakeMaker::VERSION >= 6.3002))
		? ('LICENSE'=> 'GPL')
		: ()),
	'LIBS' => [''],	# e.g., '-lm'
	'DEFINE' => '',	# e.g., '-DHAVE_SOMETHING'
	'INC' => '',	# e.g., '-I/usr/include/other'
	EXE_FILES => ['bin/example_abuse_check'],
	PL_FILES	=> {},
	CONFIGURE_REQUIRES => {
		'ExtUtils::MakeMaker' => 6.64,	# Minimum version for TEST_REQUIRES
	}, PREREQ_PM => {
		'IO::Socket::INET' => 0,
		'MIME::QuotedPrint' => 0,
		'MIME::Base64' => 0,
		'Object::Configure' => 0,
		'Params::Get' => 0,
		'Params::Validate::Strict' => 0,
		'Params::Validate::Strict' => 0,
		'Socket' => 0,
	}, TEST_REQUIRES => {
		'FindBin' => 0,
		'MIME::Base64' => 0,
		'MIME::QuotedPrint' => 0,
		'POSIX' => 0,
		'Scalar::Util' => 0,
		'Test::DescribeMe' => 0,
		'Test::Most' => 0,
	}, dist => $dist,
	clean		=> { FILES => 'Mail-Message-Abuse-*' },
	# META_ADD => {
		# provides => {}
	# },
	META_MERGE => {	# https://perldoc.perl.org/CPAN::Meta::Spec
		'meta-spec' => { version => 2 },
		resources => {
			homepage => 'https://metacpan.org/pod/Mail::Message::Abuse',
			repository => {
				repository => 'https://github.com/nigelhorne/Mail-Message-Abuse',
				type => 'git',
				url => 'git://github.com/nigelhorne/Mail-Message-Abuse.git',
				web => 'https://github.com/nigelhorne/Mail-Message-Abuse',
				# license => 'http://dev.perl.org/licenses/',
			}, bugtracker => {
				web => 'https://rt.cpan.org/Public/Dist/Display.html?Name=Mail-Message-Abuse',
				url => 'https://rt.cpan.org/Public/Dist/Display.html?Name=Mail-Message-Abuse',
				# web => 'https://github.com/nigelhorne/Mail-Message-Abuse/issues',
				# url => 'https://github.com/nigelhorne/Mail-Message-Abuse/issues',
				mailto => 'bug-Mail-Message-Abuse@rt.cpan.org'
			}
		},
	},
	MIN_PERL_VERSION	=> '5.008'
);
