/* 
 * eco2exe.c v0.01 Andrew Kieschnick <andrewk@mail.utexas.edu>
 *
 * converts MIPSEL-LE ecoff to PS-X EXE
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAXSEC 64

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

void usage(void)
{
  printf("Usage: eco2exe [-p] <filename>\n\n");
  printf("\t-p\t\tpatch to work on normal psx\n");
  printf("\t<filename>\ta MIPSEL-LE file to convert to PS-X EXE\n\n");
  exit(0);
}

int main(int argc, char *argv[])
{
  FILE *ecoff;
  FILE *exe;
  unsigned char data[4];
  char filename[256];
  int i,j,n;
  int nscns;
  int nload=0;
  int load[MAXSEC];
  unsigned int sec_paddr[MAXSEC];
  unsigned int sec_size[MAXSEC];
  unsigned int sec_scnptr[MAXSEC];
  unsigned int entry;
  unsigned int start;
  unsigned int end;
  unsigned int span;
  unsigned int size;
  unsigned int address;
  unsigned int pc0;
  unsigned char patch=0; /* 0=don't, 1=do */

  printf("eco2exe v0.01 Andrew Kieschnick <andrewk@mail.utexas.edu>\n\n");

  if ((argc<2)||(argc>3))
    usage();

  for(i=1;i<argc;i++)
    {
      if(argv[i][0]=='-')
        switch(argv[i][1])
          {
          case 'P':
          case 'p':
	    patch=1;
	    break;
	  default:
	    usage();
	  }
      else
	{
	  strncpy(filename,argv[i],sizeof(filename)-5);
	  filename[sizeof(filename)-5]=0;
	}
    }

  ecoff=fopen(filename, "rb");

  if (!ecoff)
    {
      printf("ERROR: Can't open %s\n",filename);
      exit(-1);
    }

  strcat(filename, ".exe"); /* output filename is same as input but with .exe appended */

  exe=fopen(filename, "wb");

  if (!exe)
    {
      printf("ERROR: Can't open %s\n",filename);
      exit(-1);
    }

  /* --- file header --- */
  fseek(ecoff, 0, SEEK_SET);
  for(i=0;i<2;i++)
    data[i]=fgetc(ecoff);

  if ((data[0]!=0x62)||(data[1]!=0x01))
    {
      printf("ERROR: Not a MIPSEL-LE binary!\n");
      exit(-1);
    }

  for(i=0;i<2;i++)
    data[i]=fgetc(ecoff);

  nscns=data[0]+(data[1]<<8); /* f_nscns, offset 0x02 */

  if ((nscns<1)||(nscns>MAXSEC))
    {
      printf("ERROR: %d sections (unsupported)\n",nscns);
      exit(-1);
    }

  /* --- optional header: entry point (aouthdr offset 0x10 -> file offset 0x24) --- */
  fseek(ecoff, 0x24, SEEK_SET);
  for(i=0;i<4;i++)
    data[i]=fgetc(ecoff);
  entry=char2int(data);

  /* --- section headers (start at 0x4c, 0x28 bytes each) ---
     name @+0x00, s_paddr @+0x08, s_size @+0x10, s_scnptr @+0x14 */
  for(i=0;i<nscns;i++)
    {
      fseek(ecoff, 0x4c+i*0x28+0x08, SEEK_SET);
      for(j=0;j<4;j++)
	data[j]=fgetc(ecoff);
      sec_paddr[i]=char2int(data);

      fseek(ecoff, 0x4c+i*0x28+0x10, SEEK_SET);
      for(j=0;j<4;j++)
	data[j]=fgetc(ecoff);
      sec_size[i]=char2int(data);

      fseek(ecoff, 0x4c+i*0x28+0x14, SEEK_SET);
      for(j=0;j<4;j++)
	data[j]=fgetc(ecoff);
      sec_scnptr[i]=char2int(data);
    }

  /* keep the sections that actually have data in the file (bss has no
     file data and is cleared at runtime), sorted by load address */
  for(i=0;i<nscns;i++)
    if ((sec_size[i]!=0)&&(sec_scnptr[i]!=0))
      {
	for(n=nload;n>0;n--)
	  {
	    if (sec_paddr[load[n-1]]<=sec_paddr[i])
	      break;
	    load[n]=load[n-1];
	  }
	load[n]=i;
	nload++;
      }

  if (nload==0)
    {
      printf("ERROR: no loadable sections\n");
      exit(-1);
    }

  start=sec_paddr[load[0]];
  end=start;
  for(n=0;n<nload;n++)
    {
      i=load[n];
      if ((sec_paddr[i]+sec_size[i])>end)
	end=sec_paddr[i]+sec_size[i];
    }

  span=end-start; /* image is the whole span, gaps included */
  size=span;

  if (patch)
    {
      pc0=start+size;
      size+=16;
    }
  else
    pc0=entry;

  fprintf(exe, "PS-X EXE");
  int2char(0, data);
  fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* text */
  fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* data */
  int2char(pc0, data);
  fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* pc0 */
  int2char(0, data);
  fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* gp0 */
  int2char(start, data);
  fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]); /* t_addr */
  int2char(size, data);
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

  /* copy every loadable section to its address, zero filling the gaps */
  address=start;
  for(n=0;n<nload;n++)
    {
      i=load[n];
      while (address<sec_paddr[i])
	{
	  fprintf(exe, "%c", 0);
	  address++;
	}
      fseek(ecoff, sec_scnptr[i], SEEK_SET);
      for(j=0;j<(int)sec_size[i];j++)
	{
	  int c=fgetc(ecoff);
	  fprintf(exe, "%c", (c==EOF)?0:c);
	  address++;
	}
    }

  /* never write less than the t_size we advertised */
  while (address<(start+span))
    {
      fprintf(exe, "%c", 0);
      address++;
    }

  if(patch)
    {
      int2char(0x0c00400c, data); /* jal 0x80010030 */
      fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]);
      int2char(0, data); /* nop */
      fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]);
      int2char(0x08000000 + ((entry&0x03ffffff)>>2),data); /*j realpc0 */
      fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]);
      int2char(0, data); /* nop */
      fprintf(exe, "%c%c%c%c", data[0], data[1], data[2], data[3]);
    }

  fclose(exe);
  fclose(ecoff);

  return 0;
}
