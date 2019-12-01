/**  @file   main.c
 *   @author jithware
 *   @brief main definitions
 */

#include <apr.h>
#include <apr_getopt.h>

#include <main.h>

int callback_signal(int signum)
{
	if (_opts.verbose)
	{
		printf("Received signal: %i\n", signum);
	}

	switch (signum)
	{
		case SIGTERM:

			return 1;

		case SIGINT:

			return 1;

		#ifndef WIN32
		case SIGTSTP:

			return 0;

		case SIGHUP:

			return 0;

		#endif
	}

	return 0;
}

int main(int argc, const char * const argv[])
{
	apr_status_t rv;
	apr_getopt_t *opt;
	apr_pool_t *mp;
	int optch, success;
	const char *optarg;

	//apr init
	rv = apr_app_initialize(&argc, &argv, NULL);
	status(rv,TRUE);

	//main memory pool
	rv = apr_pool_create(&mp, NULL);
	status(rv,TRUE);

	//get options
	apr_getopt_init(&opt, mp, argc, argv);
	while ((rv = apr_getopt_long(opt, OPTIONS, &optch, &optarg)) == APR_SUCCESS)
	{
		switch (optch)
		{
			case OPTION_INTERFACE:
				_opts.interface = (char*)optarg;
				break;

			case OPTION_SOURCE:
				_opts.source = (char*)optarg;
				break;

			case OPTION_DESTINATION:
				_opts.destination = (char*)optarg;
				break;

			case OPTION_UID:
				_opts.uid = (char*)optarg;
				break;

			case OPTION_GET:
				_opts.get = (char*)optarg;
				break;

			case OPTION_STDIN:
				_opts.stdin = TRUE;
				break;

			case OPTION_PREPEND:
				_opts.prepend = (char*)optarg;
				break;

			case OPTION_TEXT:
				_opts.text = (char*)optarg;
				break;

			case OPTION_STREAM:
				_opts.stream = (char*)optarg;
				break;

			case OPTION_CAPFILE:
				_opts.capfile = (char*)optarg;
				break;

			case OPTION_AVOID:
				_opts.avoid = (char*)optarg;
				break;

			case OPTION_PATTERN:
				_opts.pattern = (char*)optarg;
				break;

			case OPTION_SEARCH:
				_opts.search = (char*)optarg;
				break;

			case OPTION_GIVEUP:
				_opts.giveup = (char*)optarg;
				break;

			case OPTION_IGNORE:
				_opts.ignore = (char*)optarg;
				break;

			case OPTION_BSSID:
				_opts.bssid = (char*)optarg;
				break;

			case OPTION_DADDR:
				_opts.daddr = (char*)optarg;
				break;

			case OPTION_BLOCKSIZE:
				_opts.blocksize = (char*)optarg;
				break;

			case OPTION_SILENT:
				_opts.silent = TRUE;
				break;

			case OPTION_RECURSIVE:
				_opts.recursive = TRUE;
				break;

			case OPTION_VERIFY:
				_opts.verify = TRUE;
				break;

			case OPTION_RANDUID:
				_opts.randuid = TRUE;
				break;

			case OPTION_FILTER:
				_opts.filter = TRUE;
				break;

			#ifdef HAVE_WAPI
			case OPTION_MONITOR:
				_opts.monitor = TRUE;
				break;

			case OPTION_CHANNEL:
				_opts.channel = (char*)optarg;
				break;
			#endif

			case OPTION_VERBOSE:
				_opts.verbose = TRUE;
				break;

			case OPTION_DEBUG:
				_opts.debug++;
				break;

			case OPTION_VERSION:
				_opts.version = TRUE;
				break;

			case OPTION_HELP:
				_opts.help = TRUE;
				break;

			default:
				break;

		}
	}

	if (rv != APR_EOF)
	{
		fprintf(stderr, "use -h or --help\n");
		exit(EXIT_FAILURE);
	}

	success = wtftpd_start(&_opts);

	if (success == -1)
	{
		fprintf(stderr, "Error starting wtftpd.\n");
		exit(EXIT_FAILURE);
	}

	if (success)
	{
		//create thread for listening to signals (exits when callback returns 1)
		#ifndef WIN32
		apr_setup_signal_thread();
		apr_signal_thread(callback_signal);
		#else
		//signal thread not supported so just yield to other threads
		apr_thread_yield();
		#endif
	}

	apr_pool_destroy(mp);

	apr_terminate();

	return EXIT_SUCCESS;
}
