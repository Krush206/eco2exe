/*
 * eco2exe.c v0.01 Andrew Kieschnick <andrewk@mail.utexas.edu>
 *
 * converts MIPSEL-LE ecoff to PS-X EXE
 *
 * THIS SOURCE WAS MODIFIED (SLIGHTLY) TO WORK UNDER DOS
 * IF YOU USE UNIX, GET THE THE UNMODIFIED SOURCE
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h> // tolower/upper

#define VERBOSE 1

#define USE_ECO2EXE_SOURCE
#define COMBINE_TMP_FILENAME "COMBINE.TMP"


unsigned int char2int(unsigned char *foo)
{
	return foo[3]*16777216 + foo[2]*65536 + foo[1]*256 + foo[0];
}

void int2char(unsigned int foo, unsigned char *bar)
{
	bar[3]=foo>>24;
	bar[2]=foo>>16;
	bar[1]=foo>>8;
	bar[0]=foo;
}


// ecoff a.out format from siocon src
typedef struct filehdr {
	unsigned short	f_magic;	//00 -02 /* magic number */
	unsigned short	f_nscns;	//02 -04 /* number of sections */
	unsigned int		f_timdat;	// 04 -08 /* time & date stamp */
	unsigned int		f_symptr;	// 08 -12 /* file pointer to symbolic header */
	unsigned int		f_nsyms;	// 12 -16 /* sizeof(symbolic hdr) */
	unsigned short	f_opthdr; // 16 -18		/* sizeof(optional hdr) */
	unsigned short	f_flags; // 18 -20		/* flags */
}FILEHDR;

typedef	struct aouthdr {
	unsigned short	magic;   // 20 -22		 00 -02 0x62 and 0x01
	unsigned short	vstamp;  // 22 -24
	unsigned int	tsize;  // 24 -28
	unsigned int	dsize;  //28 -32
	unsigned int	bsize;  //32 -36
	unsigned int	entry; //36 -40
	unsigned int	text_start;  //40 -44
	unsigned int	data_start;	//44 -48
	unsigned int	bss_start; //48 -52
	unsigned int	gprmask; //52 -56
	unsigned int	cprmask[4]; //56 -72
	unsigned int	gp_value; // 72 -76
} AOUTHDR;


typedef struct scnhdr { // 40bytes
	char		s_name[8];		/* 76  - 84 section name */
	unsigned int		s_paddr;		/* 84  - 88 physical address, aliased s_nlib */
	unsigned int		s_vaddr;		/* 88  - 92 virtual address */
	unsigned int		s_size;			/* 92  - 96 section size */
	unsigned int		s_scnptr;		/* 96  - 100 file ptr to raw data for section */
	unsigned int		s_relptr;		/* 100 - 104 file ptr to relocation */
	unsigned int		s_lnnoptr;		/* 104 - 108 file ptr to gp histogram */
	unsigned short	s_nreloc;	/* 108 - 110 number of relocation entries */
	unsigned short	s_nlnno;	/* 110 - 112 number of gp histogram entries */
	unsigned int		s_flags;		/* 112 - 116 flags */
}SCNHDR;



typedef	struct allEcoffHdr{
	FILEHDR fileHDR;
	AOUTHDR ecoHDR;
	SCNHDR  sections[10];
} ECOHDRS;
int main(int argc, char *argv[])
{
	int patch;
	char filename[256];
	FILE *ecoff;
	FILE *exe;
	unsigned char data[4];
	int i,j,k=2;
	unsigned int header_data[14];
	unsigned int ecoff_size;
	unsigned int address;
	unsigned int pc0;
	unsigned char ecoffpatch=1; /* 0=don't, 1=do */
	ECOHDRS ecoffHDR;

	memset(header_data, 0, sizeof header_data);
	memset(data, 0, sizeof data);

	//float lit sections PITA
	int litPos=-1;
	int litVal[3];


  if (argc != 3)
    return 1;

	strncpy(filename,argv[1],256);


	ecoff=fopen(filename, "rb");

	if (!ecoff)
	{
		printf("100 ERROR: Can't open %s\n",filename);
		return 1;
	}

	//strcat(filename, ".exe"); /* output filename is same as input but with .exe appended */


	exe=fopen(argv[2], "wb");

	if (!exe)
	{
		printf("2 ERROR: Can't open %s\n",filename);

		return 2;
	}

	fseek(ecoff,0,SEEK_SET);
	fread(&ecoffHDR, sizeof(ecoffHDR),1,  ecoff);
	fseek(ecoff,0,SEEK_SET);

	for(i=0;i<2;i++)
		fscanf(ecoff, "%c", &data[i]);
	//0x02




	if (memcmp((char *) &ecoffHDR, "PS-X EXE", 8) == 0)
	{
		int size;
		char *exedata;

		if(VERBOSE)
			printf("%s is PS-X EXE. \n",filename);

		fseek(ecoff,0,SEEK_END);
		size = ftell(ecoff);
		fseek(ecoff,0,SEEK_SET);

		fseek(exe,0,SEEK_SET);





		exedata = malloc(size);

		if(exedata == NULL)
		{
			printf("PS-X EXE binary memory failed allocation\n");
			return 3;
		}

		memset(exedata, 0,size);

		fread(exedata, sizeof(char),size,  ecoff);
		fflush(ecoff); //force update


		fwrite(exedata, sizeof(char),size, exe);
		fflush(exe); //force update



		fclose(exe);
		fclose(ecoff);
		free(exedata);

		fflush(stdout);
		return 0; // return ok
	}
	else if ( ((char *)&ecoffHDR)[0] == 'C' &&  ((char *)&ecoffHDR)[1] == 'P' &&  ((char *)&ecoffHDR)[2] == 'E')
	{
		printf("CRITICAL ERROR - %s is a CPE binary file which is not supported.\n",filename);
		printf("Create a PS-X EXE with CPE2X or CPE2PSX and try again.\n");
		return 111;
	}
	else if (( ((char *)&ecoffHDR)[0]==0x62)||( ((char *)&ecoffHDR)[1]==0x01))
	{



		//MIPS ECOFF A.OUT format -  NET YAROZE

		if(VERBOSE)
		{
			printf("ECOFF NET YAROZE A.OUT binary - sections: %d\n", ecoffHDR.fileHDR.f_nscns);


			printf("ecoffHDR.ecoHDR.entry (pc) 0x%X \n", ecoffHDR.ecoHDR.entry );
			printf("ecoffHDR.ecoHDR.gp_value 0x%X \n",ecoffHDR.ecoHDR.gp_value);

		}

		for(i=0;i<ecoffHDR.fileHDR.f_nscns;i++)
		{

			/*
			 *  loading
			 * 	(long)STYP_TEXT, {_TEXT},
			(long)STYP_RDATA, {_RDATA},
			(long)STYP_DATA, {_DATA},
			(long)STYP_SDATA, {_SDATA}

			 */

#define	_TEXT	".text"
#define	TEXT_POS 2

#define	_RDATA	".rdata"
#define	RDATA_POS 5

#define	_DATA	".data"
#define	DATA_POS 8


#define	_SDATA	".sdata"
#define	SDATA_POS 11


			if(VERBOSE)
				printf("\nECOFF  sections: %d/%d %s\n", i+1,ecoffHDR.fileHDR.f_nscns ,  ecoffHDR.sections[i].s_name);

			if(  !strcmp( ecoffHDR.sections[i].s_name, _TEXT))
			{
				k =TEXT_POS;//first section
				header_data[k]= ecoffHDR.sections[i].s_paddr;  //  scnhdr.s_paddr - 84  - 88 physical address, aliased s_nlib

				if(VERBOSE)
					printf("s_paddr: 0x%X\n",header_data[k] );

				k++;

				header_data[k]= ecoffHDR.sections[i].s_size;  // scnhdr.s_size - 92  - 96 section size
				if(VERBOSE)
					printf("s_size: 0x%X (%d)\n",header_data[k],header_data[k] );

				k++;

				header_data[k]= ecoffHDR.sections[i].s_scnptr;  // scnhdr.s_scnptr;		/* 96  - 100 file ptr to raw data for section

				if(VERBOSE)
					printf("s_scnptr: 0x%X\n",header_data[k] );

				k++;

			}
			else   if(  !strcmp( ecoffHDR.sections[i].s_name, _RDATA))
			{
				k = RDATA_POS;//2 section

				header_data[k]= ecoffHDR.sections[i].s_paddr;  //  scnhdr.s_paddr - 84  - 88 physical address, aliased s_nlib

				if(VERBOSE)
					printf("s_paddr: 0x%X\n",header_data[k] );

				k++;

				header_data[k]= ecoffHDR.sections[i].s_size;  // scnhdr.s_size - 92  - 96 section size

				if(VERBOSE)
					printf("s_size: 0x%X (%d)\n",header_data[k],header_data[k] );

				k++;

				header_data[k]= ecoffHDR.sections[i].s_scnptr;  // scnhdr.s_scnptr;		/* 96  - 100 file ptr to raw data for section

				if(VERBOSE)
					printf("s_scnptr: 0x%X\n",header_data[k] );

				k++;

			}
			else   if(  !strcmp( ecoffHDR.sections[i].s_name, _DATA))
			{
				k = DATA_POS;//3 section

				header_data[k]= ecoffHDR.sections[i].s_paddr;  //  scnhdr.s_paddr - 84  - 88 physical address, aliased s_nlib

				if(VERBOSE)
					printf("s_paddr: %X\n",header_data[k] );

				k++;

				header_data[k]= ecoffHDR.sections[i].s_size;  // scnhdr.s_size - 92  - 96 section size

				if(VERBOSE)
					printf("s_size: 0x%X (%d)\n",header_data[k],header_data[k] );

				k++;

				header_data[k]= ecoffHDR.sections[i].s_scnptr;  // scnhdr.s_scnptr;		/* 96  - 100 file ptr to raw data for section


				if(VERBOSE)
					printf("s_scnptr: 0x%X\n",header_data[k] );

				k++;


			}

			// last section can be either SDATA or .LIT
			// https://www3.physnet.uni-hamburg.de/physnet/Tru64-Unix/HTML/APS31DTE/DOCU_013.HTM

			else   if( !strcmp( ecoffHDR.sections[i].s_name,  _SDATA))
			{
				k = SDATA_POS;//4 section
				header_data[k]= ecoffHDR.sections[i].s_paddr;  //  scnhdr.s_paddr - 84  - 88 physical address, aliased s_nlib

				if(VERBOSE)
					printf("s_paddr: 0x%X\n",header_data[k] );

				k++;

				header_data[k]= ecoffHDR.sections[i].s_size;  // scnhdr.s_size - 92  - 96 section size


				if(VERBOSE)
					printf("s_size: 0x%X (%d)\n",header_data[k],header_data[k] );

				k++;

				header_data[k]= ecoffHDR.sections[i].s_scnptr;  // scnhdr.s_scnptr;		/* 96  - 100 file ptr to raw data for section

				if(VERBOSE)
					printf("s_scnptr: 0x%X\n",header_data[k] );

				k++;

			}
			else   if(strstr(  ecoffHDR.sections[i].s_name, ".lit8") > 0)  // C:\PSX3 compiler soft float stuff??
			{

				if(VERBOSE)
				{
					printf("\n\nWARNING: Experimental section detected: %s\n",  ecoffHDR.sections[i].s_name);
					printf("WARNING: Conversion with this section is buggy and may crash your program!!!\n");
					printf("WARNING: Address space in question: 0x%X\n",ecoffHDR.sections[i].s_paddr );
					printf("WARNING: Size in question: 0x%X (%d) bytes \n",ecoffHDR.sections[i].s_size, ecoffHDR.sections[i].s_size );
					printf("WARNING: This typically happens with the C:\\PSX3 compiler when using software floats.\n" );
					printf("WARNING: If your program crashes:\n" );
					printf("WARNING: 1) Note address of crash, check mapfile, remove floats or doubles.  \n" );
					printf("WARNING: 2) Use a different compiler..... Sorry :/ \n" );
					printf("WARNING: 3) Fix this code?? :/ \n" );
					printf("WARNING:  \n" );

					printf(".lit8: s_paddr: 0x%X\n",ecoffHDR.sections[i].s_paddr );
					printf(".lit8: s_size: 0x%X (%d)\n",ecoffHDR.sections[i].s_size, ecoffHDR.sections[i].s_size );
					printf(".lit8: s_scnptr: 0x%X\n",ecoffHDR.sections[i].s_scnptr );
					printf("\n");

				}
				else
				{
					printf("\n\nWARNING: Experimental section detected: %s\n",  ecoffHDR.sections[i].s_name);
					printf("WARNING: The psx.exe may results in crashing.\n");
					printf("WARNING: Turn verbose on -v to see full message.\n");

				}






				litPos=i;

				litVal[0]= ecoffHDR.sections[i].s_paddr;  //  scnhdr.s_paddr - 84  - 88 physical address, aliased s_nlib

				if(VERBOSE)
					printf("s_paddr: 0x%X\n",litVal[0]);



				litVal[1]= ecoffHDR.sections[i].s_size;// fixes issue on RS +0x100;  // scnhdr.s_size - 92  - 96 section size

				if(VERBOSE)
					printf("s_size: 0x%X (%d)\n",litVal[1], litVal[1] );



				litVal[2]= ecoffHDR.sections[i].s_scnptr;  // s


			}
			else   if( strstr(  ecoffHDR.sections[i].s_name, ".lit4") > 0)  // C:\PSX3 compiler soft float stuff??
			{
				printf("Skipped: s_paddr: 0x%X\n",ecoffHDR.sections[i].s_paddr );
				printf("Skipped: s_size: 0x%X (%d)\n",ecoffHDR.sections[i].s_size, ecoffHDR.sections[i].s_size );
				printf("Skipped: s_scnptr: 0x%X\n",ecoffHDR.sections[i].s_scnptr );
				printf("\n");
				//continue;


				printf("litPos : %d\n",litPos);
				if(litPos==-1)
				{
					litPos=i;

					if(VERBOSE)
					{
						printf("\n\nWARNING: Experimental section detected: %s\n",  ecoffHDR.sections[i].s_name);
						printf("WARNING: Conversion with this section is buggy and may crash your program!!!\n");
						printf("WARNING: Address space in question: 0x%X\n",ecoffHDR.sections[i].s_paddr );
						printf("WARNING: Size in question: 0x%X (%d) bytes \n",ecoffHDR.sections[i].s_size, ecoffHDR.sections[i].s_size );
						printf("WARNING: This typically happens with the C:\\PSX3 compiler when using software floats.\n" );
						printf("WARNING: If your program crashes:\n" );
						printf("WARNING: 1) Note address of crash, check mapfile, remove floats or doubles.  \n" );
						printf("WARNING: 2) Use a different compiler..... Sorry :/ \n" );
						printf("WARNING: 3) Fix this code?? :/ \n" );
						printf("WARNING:  \n" );


						printf(".lit4: s_paddr: 0x%X\n",ecoffHDR.sections[i].s_paddr );
						printf(".lit4: s_size: 0x%X (%d)\n",ecoffHDR.sections[i].s_size, ecoffHDR.sections[i].s_size );
						printf(".lit4: s_scnptr: 0x%X\n",ecoffHDR.sections[i].s_scnptr );
						printf("\n");
					}
					else
					{
						printf("\n\nWARNING: Experimental section detected: %s\n",  ecoffHDR.sections[i].s_name);
						printf("WARNING: The psx.exe may results in crashing.\n");
						printf("WARNING: Turn verbose on -v to see full message.\n");

					}


					litVal[0]= ecoffHDR.sections[i].s_paddr;  //  scnhdr.s_paddr - 84  - 88 physical address, aliased s_nlib

					if(VERBOSE)
						printf("s_paddr: 0x%X\n",litVal[0]);



					litVal[1]= ecoffHDR.sections[i].s_size;// fixes issue on RS +0x100;  // scnhdr.s_size - 92  - 96 section size

					if(VERBOSE)
						printf("s_size: 0x%X (%d)\n",litVal[1], litVal[1] );



					litVal[2]= ecoffHDR.sections[i].s_scnptr;  // scnhdr.s_scnptr;		/* 96  - 100 file ptr to raw data for section

					if(VERBOSE)
						printf("s_scnptr: 0x%X\n",litVal[2] );
				}
				else
				{
					if(VERBOSE)
						printf(".lit8 processed, now adding .lit4 size \n" );


					//litVal[0]= ecoffHDR.sections[i].s_paddr;  //  scnhdr.s_paddr - 84  - 88 physical address, aliased s_nlib

					if(VERBOSE)
						printf("s_paddr: 0x%X\n",litVal[0]);



					litVal[1]+= ecoffHDR.sections[i].s_size;// fixes issue on RS +0x100;  // scnhdr.s_size - 92  - 96 section size

					if(VERBOSE)
						printf("s_size: 0x%X (%d)\n",litVal[1], litVal[1] );



					//	litVal[2]= ecoffHDR.sections[i].s_scnptr;  // scnhdr.s_scnptr;		/* 96  - 100 file ptr to raw data for section

					if(VERBOSE)
						printf("s_scnptr: 0x%X\n",litVal[2] );

				}



			}

			else // not used
			{
				if(VERBOSE)
				{
					printf("Skipped: s_paddr: 0x%X\n",ecoffHDR.sections[i].s_paddr );
					printf("Skipped: s_size: 0x%X (%d)\n",ecoffHDR.sections[i].s_size, ecoffHDR.sections[i].s_size );
					printf("Skipped: s_scnptr: 0x%X\n",ecoffHDR.sections[i].s_scnptr );
					printf("\n");
				}
			}







			/*


				{_TEXT},
				(long)STYP_DATA, {_DATA},
				    (long)STYP_RDATA, {_RDATA},

				    (long)STYP_SDATA, {_SDATA}



				    if ( s->s_flags & section_types[ i ].flags &&
	    !strcmp( s->s_name, section_types[i].name)) {
	    return 1;
	}


				// 84b start of scnhdr.s_paddr sizeof(scnhdr) = 40b
				fseek(ecoff, 0x54+i*0x28, SEEK_SET); // 84 (i*40)
				for(j=0;j<4;j++)
					fscanf(ecoff, "%c", &data[j]);
				header_data[k]=char2int(data); //  scnhdr.s_paddr - 84  - 88 physical address, aliased s_nlib
				k++;
				fseek(ecoff, 0x54+i*0x28+0x08, SEEK_SET);
				for(j=0;j<4;j++)
					fscanf(ecoff, "%c", &data[j]);
				header_data[k]=char2int(data); // scnhdr.s_size - 92  - 96 section size
				k++;
				for(j=0;j<4;j++)
					fscanf(ecoff, "%c", &data[j]);
				header_data[k]=char2int(data); // scnhdr.s_scnptr;		96  - 100 file ptr to raw data for section
				k++;
			 */
		}



		if(litPos>0)
		{
			if(VERBOSE)
			{
				printf("\nProcessing litPos was %d \n", litPos);
				printf("s_paddr: 0x%X\n",litVal[0]);
				printf("s_size: 0x%X (%d)\n", litVal[1], litVal[1]);
				printf("s_scnptr: 0x%X\n", litVal[2]);
				printf("\n");
			}
#define	_DATA	".data"
#define	DATA_POS 8

#if 1
			// both work - I'm confused?
#if 1
			header_data[SDATA_POS] = litVal[0]; // replace address with lit
			header_data[SDATA_POS+1] += litVal[1]; //add size
			header_data[SDATA_POS+2] = litVal[2]; // not sure

#else
			//header_data[DATA_POS] = litVal[0]; // replace address with lit
			header_data[DATA_POS+1] += litVal[1]; //add size
			//header_data[DATA_POS+2] = litVal[2]; // not sure
#endif

#endif

		}



	}





	k =2;//first section

	fseek(ecoff, 0x24, SEEK_SET);
	//0x24 = 36bytes: cprmask 4*4 bytes

	for(i=0;i<4;i++)
		fscanf(ecoff, "%c", &data[i]);

	// 40bytes
	header_data[0]=char2int(data); //entry 0x80128180

	fseek(ecoff, 0x48, SEEK_SET);
	//72bytes  gp_value
	for(i=0;i<4;i++)
		fscanf(ecoff, "%c", &data[i]);

	header_data[1]=char2int(data); // gp_value 0x80131d40



	if(VERBOSE)
	{
		printf("ecoffHDR.ecoHDR.entry (pc) 0x%X \n", ecoffHDR.ecoHDR.entry );
		printf("ecoffHDR.ecoHDR.gp_value 0x%X \n",ecoffHDR.ecoHDR.gp_value);
		printf("reread: entry (pc) 0x%X \n",header_data[0] );
		printf("reread: gp_value 0x%X \n",header_data[1]);
	}


#if 0 //old
	for(i=0;i<4;i++)
	{
		char section[8]={0};
		fseek(ecoff, 0x4C+i*0x28, SEEK_SET); // 84 (i*40)
		fscanf(ecoff, "%c", &section[0]);
		fscanf(ecoff, "%c", &section[1]);
		fscanf(ecoff, "%c", &section[2]);
		fscanf(ecoff, "%c", &section[3]);
		fscanf(ecoff, "%c", &section[4]);
		fscanf(ecoff, "%c", &section[5]);
		fscanf(ecoff, "%c", &section[6]);
		fscanf(ecoff, "%c", &section[7]);
		printf("section: %d %s\n",i, section);

		// 84b start of scnhdr.s_paddr sizeof(scnhdr) = 40b
		fseek(ecoff, 0x54+i*0x28, SEEK_SET); // 84 (i*40)
		for(j=0;j<4;j++)
			fscanf(ecoff, "%c", &data[j]);
		header_data[k]=char2int(data); //  scnhdr.s_paddr - 84  - 88 physical address, aliased s_nlib
		printf("s_paddr: %X\n",header_data[k] );
		k++;
		fseek(ecoff, 0x54+i*0x28+0x08, SEEK_SET);
		for(j=0;j<4;j++)
			fscanf(ecoff, "%c", &data[j]);
		header_data[k]=char2int(data); // scnhdr.s_size - 92  - 96 section size
		printf("s_size:  %X\n",header_data[k] );
		k++;
		for(j=0;j<4;j++)
			fscanf(ecoff, "%c", &data[j]);
		header_data[k]=char2int(data); // scnhdr.s_scnptr;		/* 96  - 100 file ptr to raw data for section
		printf("s_scnptr:  %X\n",header_data[k] );
		k++;
	}


#define	_TEXT	".text"
#define	TEXT_POS 2

#define	_RDATA	".rdata"
#define	RDATA_POS 5

#define	_DATA	".data"
#define	DATA_POS 8


#define	_SDATA	".sdata"
#define	SDATA_POS 11

#endif
	//0x80129d40 - 0x80120000 + 0x130 = 0x9E70 = 40560
	ecoff_size=(header_data[SDATA_POS]-header_data[TEXT_POS])+header_data[SDATA_POS+1];

	if(ecoffpatch)
	{
		pc0=header_data[TEXT_POS]+ecoff_size;
		ecoff_size+=16;


		if(VERBOSE)
		{
			printf("ECOFF new patched: entry (pc) 0x%X = PC 0x%X  + size %d  \n",pc0 , header_data[TEXT_POS], ecoff_size-16);
			printf("ECOFF new patched: size (%d) 0x%X = 0x%X =  (%d+16) \n",ecoff_size, ecoff_size, ecoff_size, ecoff_size-16 );
		}

	}
	else
		pc0=header_data[0];


	if(VERBOSE)
	{
		printf("ecoffHDR.ecoHDR.entry (pc) 0x%u\n", pc0 );
	}


	fprintf(exe, "PS-X EXE");
	int2char(0, data);
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* text */
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* data */
	int2char(pc0, data);
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* pc0 */
	int2char(0, data);
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* gp0 */
	int2char(header_data[2], data);
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* t_addr */
	int2char(ecoff_size, data);
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* t_size */
	int2char(0, data);
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* d_addr */
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* d_size */
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* b_addr */
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* b_size */
	int2char(0x801fff00, data);
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* s_addr */
	int2char(0, data);
	fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* s_size */

	for(i=0;i<1992;i++)
		fprintf(exe, "%c", 0);

	fseek(ecoff, header_data[4], SEEK_SET);
	address=header_data[2];
	for(i=0;i<header_data[3];i++)
	{
		fscanf(ecoff, "%c", &data[0]);
		fprintf(exe, "%c", data[0]);
		address++;
	}
	fseek(ecoff, header_data[7], SEEK_SET);
	if (address!=header_data[5]) /* wonder if this can happen */
		for(i=address;i<=header_data[5];i++)
		{
			fprintf(exe, "%c", 0);
			address++;
		}
	for(i=0;i<header_data[6];i++)
	{
		fscanf(ecoff, "%c", &data[0]);
		fprintf(exe, "%c", data[0]);
		address++;
	}
	fseek(ecoff, header_data[10], SEEK_SET);
	if (address!=header_data[8]) /* wonder if this can happen */
		for(i=address;i<=header_data[8];i++)
		{
			fprintf(exe, "%c", 0);
			address++;
		}
	for(i=0;i<header_data[9];i++)
	{
		fscanf(ecoff, "%c", &data[0]);
		fprintf(exe, "%c", data[0]);
		address++;
	}

	fseek(ecoff, header_data[13], SEEK_SET);
	if (address!=header_data[11]) /* wonder if this can happen */
		for(i=address;i<=header_data[11];i++)
		{
			fprintf(exe, "%c", 0);
			address++;
		}
	for(i=0;i<header_data[12];i++)
	{
		fscanf(ecoff, "%c", &data[0]);
		fprintf(exe, "%c", data[0]);
		address++;
	}

	if(ecoffpatch)
	{
		int2char(0x0c00400c, data); /* jal 0x80010030 */
		fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]);
		int2char(0, data); /* nop */
		fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]);
		int2char(0x08000000 + ((header_data[0]&0x03ffffff)>>2),data); /*j realpc0 */
		fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]);
		int2char(0, data); /* nop */
		fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]);
	}

	fclose(exe);
	fclose(ecoff);
	
	fflush(stdout);
	return 0;

}
