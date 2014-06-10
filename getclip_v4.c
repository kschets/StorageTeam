/* ################################################# *\
 * 
 * GETCLIP from Centera
 *
 * Read the C-Clip IDs from file
 * Write the CDF out in XML format to a <CLIPID>.cdf file
 * Write the BLOBs to <CLIPID>.blobx files where x is a counter
 *
\* ################################################# */

/* Compilation info :
 *
 * gcc -Wall -DPOSIX -I /usr/local/Centera_SDK/include -L /usr/local/Centera_SDK/lib/64 getclip_v4.c -lFPLibrary -lcrypto -o gc
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <FPAPI.h>

#define MAX_SIZE 256
#define BUFSIZE ( 256 + 1)
#define SHA256_DIGEST_LENGTH 32

FPInt checkAndPrintError( const char *);

int sha256_hash_string( unsigned char hash[SHA256_DIGEST_LENGTH], unsigned char outputBuffer[65])
{
	int i = 0;
	for ( i=0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf( outputBuffer + ( i*2 ), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
	return 0;
}

int hashSha256(char *path, unsigned char digest[65])
{
	FILE *file = fopen(path,"rb");
	if ( file == NULL ) 
	{
		fprintf(stderr,"Could not open %s for checksum calculation \n", path);
		exit(1);
	}
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init( &sha256 );
	const int bufSize = 32768;
	unsigned char *buffer = malloc(bufSize);
	int bytesRead = 0;
	if (!buffer) return ENOMEM;
	while((bytesRead = fread(buffer,1, bufSize, file)))
	{
		SHA256_Update(&sha256, buffer, bytesRead );
	}
	SHA256_Final(hash, &sha256);
	sha256_hash_string(hash, digest );
	fclose( file );
	free( buffer );
	return 0;
}

int main( int argc, char *argv[])
{
	FPPoolRef poolRef;
	FPInt retCode = 0;

	/* Timestamp for later use in the log */
	char timeStamp[MAX_SIZE];
	time_t curtime;
	struct tm *loctime;

	curtime = time(NULL);
	loctime = localtime( &curtime );
	strftime( timeStamp, MAX_SIZE, "%Y-%m-%d %H:%M:%S", loctime);

	/* Get the file containing the to-be migrated C-Clips from command line arguments */
	if ( argc < 6 )
	{
		fprintf(stderr, "Usage: gc <clipIDfile> <outdir> <clusterIP> <PEA file> <batchnbr>\n");
		fprintf(stderr, "Example : gc /tmp/cliplist10 /migrated 168.159.214.31 /root/c4profile3.pea 12\n");
		exit(1);
	}

	/* Open the file containing the clip IDs */
	FILE *clipFile;
	clipFile = fopen( argv[1], "r");
	char outdir[MAX_SIZE];
	char clusterip[MAX_SIZE];
	char peafile[MAX_SIZE];
	int batch;
	char batchnbr[MAX_SIZE];

	strcpy( outdir, argv[2]);
	strcpy( clusterip, argv[3]);
	strcpy( peafile, argv[4]);
	sscanf( argv[5], "%d", &batch);
	sprintf( batchnbr, "%010d", batch);

	if ( clipFile == NULL ) 
	{
		fprintf(stderr, "Can't open clip list file %s \n", argv[1]);
		exit(1);
	}

	/* Open batch logfile */
	FILE *logFile;
	char logFileName[MAX_SIZE];
	sprintf( logFileName, "%s/BATCH%s.log", argv[2], batchnbr);
	logFile = fopen( logFileName, "wt");
	if ( logFile == NULL )
	{
		fprintf(stderr, "Can't open logfile %s \n", logFileName);
		exit(1);
	}

	fprintf( logFile, "=============================================================\n");
	fprintf( logFile, "%s GETCLIP START \n", timeStamp);
	fprintf( logFile, "=============================================================\n");

	/* Creating batch output dir */
	strcat( outdir, "/BATCH");
	strcat( outdir, batchnbr );
	strcat( outdir, "/");
	if ( mkdir(outdir, 0600) == -1)
	{
		if (EEXIST == errno)
		{
			fprintf(logFile, "Directory %s already exists \n", outdir );
		}
		else
		{
			fprintf(stderr,"Directory %s could not be created \n", outdir);
			exit(1);
		}
	}

	/* Application registration info */
	const char *appVersion = "1.5";
	const char *appName = "GetClip_v4";

	/* CLUSTER IP & PEA file */
	char poolAddress[MAX_SIZE];
	strcpy( poolAddress, clusterip);
	strcat( poolAddress, "?");
	strcat( poolAddress, peafile);

	/* Actual application registration */
	FPPool_RegisterApplication( appName, appVersion );
	retCode = checkAndPrintError("Application Registration Error: ");
	fprintf(logFile,"Application registration succeeded \n");

	/* Open POOL */
	FPPool_SetGlobalOption(FP_OPTION_OPENSTRATEGY, FP_LAZY_OPEN );
	poolRef = FPPool_Open( poolAddress );
	retCode = checkAndPrintError("Pool Open Error : ");
	if (!retCode) 	
	{
		fprintf(logFile, "Pool open succeeded on %s\n", poolAddress );
		/* Read C-Clip ID's from file */
		char clipID[MAX_SIZE];
		while ( fgets( clipID, sizeof clipID, clipFile ) != NULL ) 
		{
			/* get rid of the trailing newline */
			clipID[strlen(clipID)-1] = '\0';
			fprintf(logFile,"%s: Start processing C-Clip \n", clipID);

			/* Open C-Clip */
			FPClipRef clipRef = FPClip_Open(poolRef, clipID, FP_OPEN_FLAT);
			retCode = checkAndPrintError("C-Clip Open Error : ");
			if (!retCode)
			{
				/* opening the C-Clip succeeded, now write out the CDF to file*/
				FPInt retCode = 0;
				char outfile[MAX_SIZE];
				static unsigned char cksum[65];

				FPStreamRef fpStreamRef;
				sprintf( outfile,"%s%s.cdf", outdir,clipID);

				fpStreamRef = FPStream_CreateFileForOutput( outfile, "wb" );
				retCode = checkAndPrintError("FP Stream Creation Error : ");
				
				if (!retCode)
				{
					FPClip_RawRead( clipRef, fpStreamRef );
					retCode = checkAndPrintError("C-Clip read error : ");
					
					FPStream_Close(fpStreamRef);
					retCode = checkAndPrintError("FP Stream Close Error : ");

				}
				else
					fprintf(stderr, "Cannot write the CDF to file : ");
				if (!retCode)
				{
					char mode[] = "0400";
					int i;
					i = strtol(mode,0,8);
					if ( chmod(outfile,i) < 0 )
					{
						fprintf(stderr,"%s: error in chmod(%s, %s) - %d (%s)\n",
							argv[0], outfile, mode, errno, strerror(errno));
						exit(1);
					}
					hashSha256( outfile, cksum);
					fprintf(logFile, "%s:CDF :%s:%s\n", clipID,outfile,cksum );
				}

				/* Run the TAGs and save the BLOBs */
				FPInt numTag = FPClip_GetNumTags( clipRef );
				int tagCount = 0;
				int blobCount = 0;				
				for ( tagCount = 0; tagCount < numTag; tagCount++ )
				{
					FPInt retCode = 0;
					FPTagRef tagRef = FPClip_FetchNext( clipRef );
					retCode = checkAndPrintError("Get Tag Error : ");
					if (!retCode)
					{
						/* TAG is open, check if it contains a BLOB */
						FPInt blobExists = FPTag_BlobExists( tagRef );
						if ( blobExists == 1 ) 
						{
							FPInt retCode = 0;
							char blobFile[MAX_SIZE];
							sprintf(blobFile, "%s%s.blob%d", outdir, clipID, blobCount);
							blobCount++;
							
							FPStreamRef fpStreamRef;
							fpStreamRef = FPStream_CreateFileForOutput( blobFile, "wb" );
							retCode = checkAndPrintError("FP Stream Creation Error : " );
							
							if (!retCode) 
							{
								FPTag_BlobRead( tagRef, fpStreamRef, FP_OPTION_DEFAULT_OPTIONS);
								retCode = checkAndPrintError("Reading BLOB error : " );

								FPStream_Close(fpStreamRef);
								retCode = checkAndPrintError("FP Stream Close error : " );
							}
							else 
								fprintf(stderr, "Cannot write the BLOB to file : ");
							if (!retCode) 
							{
								char mode[] = "0400";
								int i;
								i = strtol(mode,0,8);
								if ( chmod(blobFile,i) < 0 )
								{
									fprintf(stderr, "%s: error in chmod(%s,%s) - %d (%s)\n", 
										argv[0], blobFile, mode, errno, strerror(errno));
									exit(1);
								}
								hashSha256( blobFile, cksum);
								fprintf(logFile, "%s:BLOB:%s:%s\n", clipID,blobFile,cksum);
							}
							
						}
					}
					FPTag_Close(tagRef);	
				}
			}
			fprintf(logFile,"%s: Stop processing C-Clip\n",clipID);
			FPClip_Close(clipRef);
		}
	}
	curtime = time(NULL);
	loctime = localtime( &curtime );
	strftime( timeStamp, MAX_SIZE, "%Y-%m-%d %H:%M:%S", loctime);
	fprintf( logFile, "=============================================================\n");
	fprintf( logFile, "%s GETCLIP END \n", timeStamp);
	fprintf( logFile, "=============================================================\n");
	fclose( clipFile );
	return 0;
}

FPInt checkAndPrintError(const char *errorMessage)
{
    /* Get the error code of the last SDK API function call */
    FPInt errorCode = FPPool_GetLastError();
    if (errorCode != ENOERR)
    {
        FPErrorInfo errInfo;
        fprintf(stderr, errorMessage);
        /* Get the error message of the last SDK API function call */
        FPPool_GetLastErrorInfo(&errInfo);
        if (!errInfo.message) /* the human readable error message */
            fprintf(stderr, "%s\n", errInfo.errorString);
        else if (!errInfo.errorString) /* the error string corresponds to an error code */
            fprintf(stderr, "%s\n", errInfo.message);
        else
            fprintf(stderr, "%s%s%s\n",errInfo.errorString," - ",errInfo.message);
    }

    return errorCode;
}
