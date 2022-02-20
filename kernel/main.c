
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
main.c
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "fs.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "global.h"
#include "proto.h"

#define	MAX_USER		10
#define	MAX_USER_FILE	100
#define MAX_USER_DIR	5
#define	MAX_PSWD_LEN	12

#define	MAX_FILES		80
#define	MAX_DIRS		50

PUBLIC char resu[33] = {0};
char location[MAX_FILENAME_LEN] = "root";
char files[MAX_FILES][MAX_FILENAME_LEN];
int  filequeue[MAX_FILES];
int  filecount = 0;
char dirs[MAX_DIRS][MAX_FILENAME_LEN];
int  dirqueue[MAX_FILES];
int  dircount = 0;

void shabby_shell(const char * tty_name);

int isDir(const char * filepath);

void getFilepath(char *filepath, char * filename);
void getDirFilepath(char *filepath, char * filename);
void getDirpathAndFilename(char * dirpath, char * filename, char * filepath);

int getFreeFilePos();
int getFreeDirPos();
int getPosInDirQueue(char * filepath);


void addFileIntoDir(const char * dirpath, char * filename);
void deleteFileFromDir(const char * dirpath, char * filename);

void integration(char * filename);
int integration2(char * filename);
void initFS();
void welcome();
void clear();
void showProcess();
void killProcess();
void makeProcess();
void help();
void colorful();
void createFile(char * filepath, char *filename, char * buf);
void createDir(char * filepath, char *filename);
void readFile(char * filename);
void editAppand(const char * filepath, char * str);
void editCover(const char * filepath, char * str);
void deleteFile(char * filepath);
void deleteDir(char * filepath);
void ls();
void cd(char * dirname);
void cdback();



/*****************************************************************************
*                               kernel_main
*****************************************************************************/
/**
* jmp from kernel.asm::_start.
*
*****************************************************************************/
PUBLIC int kernel_main()

{

	disp_str("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"

		"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");



	int i, j, eflags, prio;

	u8  rpl;

	u8  priv; /* privilege */



	struct task * t;

	struct proc * p = proc_table;



	char * stk = task_stack + STACK_SIZE_TOTAL;



	for (i = 0; i < NR_TASKS + NR_PROCS; i++, p++, t++) {

		if (i >= NR_TASKS + NR_NATIVE_PROCS) {

			p->p_flags = FREE_SLOT;

			continue;

		}



		if (i < NR_TASKS) {     /* TASK */

			t = task_table + i;

			priv = PRIVILEGE_TASK;

			rpl = RPL_TASK;

			eflags = 0x1202;/* IF=1, IOPL=1, bit 2 is always 1 */

			prio = 15;

		}

		else {                  /* USER PROC */

			t = user_proc_table + (i - NR_TASKS);

			priv = PRIVILEGE_USER;

			rpl = RPL_USER;

			eflags = 0x202;	/* IF=1, bit 2 is always 1 */

			prio = 5;

		}



		strcpy(p->name, t->name);	/* name of the process */

		p->p_parent = NO_TASK;



		if (strcmp(t->name, "INIT") != 0) {

			p->ldts[INDEX_LDT_C] = gdt[SELECTOR_KERNEL_CS >> 3];

			p->ldts[INDEX_LDT_RW] = gdt[SELECTOR_KERNEL_DS >> 3];



			/* change the DPLs */

			p->ldts[INDEX_LDT_C].attr1 = DA_C | priv << 5;

			p->ldts[INDEX_LDT_RW].attr1 = DA_DRW | priv << 5;

		}

		else {		/* INIT process */

			unsigned int k_base;

			unsigned int k_limit;

			int ret = get_kernel_map(&k_base, &k_limit);

			assert(ret == 0);

			init_desc(&p->ldts[INDEX_LDT_C],

				0, /* bytes before the entry point

				   * are useless (wasted) for the

				   * INIT process, doesn't matter

				   */

				(k_base + k_limit) >> LIMIT_4K_SHIFT,

				DA_32 | DA_LIMIT_4K | DA_C | priv << 5);



			init_desc(&p->ldts[INDEX_LDT_RW],

				0, /* bytes before the entry point

				   * are useless (wasted) for the

				   * INIT process, doesn't matter

				   */

				(k_base + k_limit) >> LIMIT_4K_SHIFT,

				DA_32 | DA_LIMIT_4K | DA_DRW | priv << 5);

		}



		p->regs.cs = INDEX_LDT_C << 3 | SA_TIL | rpl;

		p->regs.ds =

			p->regs.es =

			p->regs.fs =

			p->regs.ss = INDEX_LDT_RW << 3 | SA_TIL | rpl;

		p->regs.gs = (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;

		p->regs.eip = (u32)t->initial_eip;

		p->regs.esp = (u32)stk;

		p->regs.eflags = eflags;



		p->ticks = p->priority = prio;



		p->p_flags = 0;

		p->p_msg = 0;

		p->p_recvfrom = NO_TASK;

		p->p_sendto = NO_TASK;

		p->has_int_msg = 0;

		p->q_sending = 0;

		p->next_sending = 0;



		for (j = 0; j < NR_FILES; j++)

			p->filp[j] = 0;



		stk -= t->stacksize;

	}



	k_reenter = 0;

	ticks = 0;



	p_proc_ready = proc_table;



	init_clock();

	init_keyboard();



	restart();



	while (1) {}

}


/*****************************************************************************
*                                get_ticks
*****************************************************************************/
PUBLIC int get_ticks()
{
	MESSAGE msg;
	reset_msg(&msg);
	msg.type = GET_TICKS;
	send_recv(BOTH, TASK_SYS, &msg);
	return msg.RETVAL;
}


/**
* @struct posix_tar_header
* Borrowed from GNU `tar'
*/
struct posix_tar_header
{				/* byte offset */
	char name[100];		/*   0 */
	char mode[8];		/* 100 */
	char uid[8];		/* 108 */
	char gid[8];		/* 116 */
	char size[12];		/* 124 */
	char mtime[12];		/* 136 */
	char chksum[8];		/* 148 */
	char typeflag;		/* 156 */
	char linkname[100];	/* 157 */
	char magic[6];		/* 257 */
	char version[2];	/* 263 */
	char uname[32];		/* 265 */
	char gname[32];		/* 297 */
	char devmajor[8];	/* 329 */
	char devminor[8];	/* 337 */
	char prefix[155];	/* 345 */
						/* 500 */
};

/*****************************************************************************
*                                untar
*****************************************************************************/
/**
* Extract the tar file and store them.
*
* @param filename The tar file.
*****************************************************************************/
void untar(const char * filename)
{
	printf("[extract `%s'", filename);
	int fd = open(filename, O_RDWR);
	assert(fd != -1);

	char buf[SECTOR_SIZE * 16];
	int chunk = sizeof(buf);

	while (1) {
		read(fd, buf, SECTOR_SIZE);
		if (buf[0] == 0)
			break;

		struct posix_tar_header * phdr = (struct posix_tar_header *)buf;

		/* calculate the file size */
		char * p = phdr->size;
		int f_len = 0;
		while (*p)
			f_len = (f_len * 8) + (*p++ - '0'); /* octal */

		int bytes_left = f_len;
		int fdout = open(phdr->name, O_CREAT | O_RDWR);
		if (fdout == -1) {
			printf("    failed to extract file: %s\n", phdr->name);
			printf(" aborted]");
			return;
		}
		printf("    %s (%d bytes)", phdr->name, f_len);
		while (bytes_left) {
			int iobytes = min(chunk, bytes_left);
			read(fd, buf,
				((iobytes - 1) / SECTOR_SIZE + 1) * SECTOR_SIZE);
			write(fdout, buf, iobytes);
			bytes_left -= iobytes;
		}
		close(fdout);
	}

	close(fd);

	printf(" done]\n");
}


/*****************************************************************************
*                                Init
*****************************************************************************/
/**
* The hen.
*
*****************************************************************************/
void Init()
{
	int fd_stdin = open("/dev_tty0", O_RDWR);
	assert(fd_stdin == 0);
	int fd_stdout = open("/dev_tty0", O_RDWR);
	assert(fd_stdout == 1);

	//printf("Init() is running ...\n");

	/* extract `cmd.tar' */
	untar("/cmd.tar");


	char * tty_list[] = { "/dev_tty0", "/dev_tty1", "/dev_tty2" };

	int i;
	for (i = 0; i < sizeof(tty_list) / sizeof(tty_list[0]); i++) {
		int pid = fork();
		if (pid != 0) { /* parent process */
		}
		else {	/* child process */
			close(fd_stdin);
			close(fd_stdout);

			shabby_shell(tty_list[i]);
			assert(0);
		}
	}

	while (1) {
		int s;
		int child = wait(&s);
		printf("child (%d) exited with status: %d.\n", child, s);
	}

	assert(0);
}


/*======================================================================*
TestA
*======================================================================*/
void TestA()
{
	for (;;);
}

/*======================================================================*
TestB
*======================================================================*/
void TestB()
{
	for (;;);
}

/*======================================================================*
TestB
*======================================================================*/
void TestC()
{
	for (;;);
}

/*****************************************************************************
*                                panic
*****************************************************************************/
PUBLIC void panic(const char *fmt, ...)
{
	char buf[256];

	/* 4 is the size of fmt in the stack */
	va_list arg = (va_list)((char*)&fmt + 4);

	vsprintf(buf, fmt, arg);

	printl("%c !!panic!! %s", MAG_CH_PANIC, buf);

	/* should never arrive here */
	__asm__ __volatile__("ud2");
}

/*****************************************************************************
*                                wx_shell
*****************************************************************************/
/**
* A very powerful shell.
*
* @param tty_name  TTY file name.
*****************************************************************************/
void shabby_shell(const char * tty_name)
{


	int fd_stdin = open(tty_name, O_RDWR);
	assert(fd_stdin == 0);
	int fd_stdout = open(tty_name, O_RDWR);
	assert(fd_stdout == 1);

	char rdbuf[128];
	char cmd[128];
	char arg1[MAX_FILENAME_LEN];
	char arg2[MAX_FILENAME_LEN];
	char filepath[MAX_FILENAME_LEN];

	colorful();
	clear();
	welcome();

	initFS();

	while (1) {

		memset(rdbuf, 0, 128);
		memset(cmd, 0, 128);
		memset(arg1, 0, MAX_FILENAME_LEN);
		memset(arg2, 0, MAX_FILENAME_LEN);
//write(1, "$ ", 2);
		printf("%s $ ", location);
		int r = read(0, rdbuf, 70);
		rdbuf[r] = 0;


		int argc = 0;
		char * argv[PROC_ORIGIN_STACK];
		char * p = rdbuf;
		char * s;
		int word = 0;
		char ch;
		do {
			ch = *p;
			if (*p != ' ' && *p != 0 && !word) {
				s = p;
				word = 1;
			}
			if ((*p == ' ' || *p == 0) && word) {
				word = 0;
				argv[argc++] = s;
				*p = 0;
			}
			p++;
		} while (ch);
		argv[argc] = 0;

		int fd = open(argv[0], O_RDWR);
		if (fd == -1) {
			if (rdbuf[0]) {
				int i = 0, j = 0;
				/* get command */
				while (rdbuf[i] != ' ' && rdbuf[i] != 0)
				{
					cmd[i] = rdbuf[i];
					i++;
				}
				i++;
				/* get arg1 */
				while (rdbuf[i] != ' ' && rdbuf[i] != 0)
				{
					arg1[j] = rdbuf[i];
					i++;
					j++;
				}
				i++;
				j = 0;
				/* get arg2 */
				while (rdbuf[i] != ' ' && rdbuf[i] != 0)
				{
					arg2[j] = rdbuf[i];
					i++;
					j++;
				}

				/* welcome */
				if (strcmp(cmd, "welcome") == 0)
				{
					welcome();
				}
				/* clear screen */
				else if (strcmp(cmd, "clear") == 0)
				{
					clear();
					welcome();
				}
				/* show process */
				else if (strcmp(cmd, "proc") == 0)
				{
					showProcess();
				}
				// kill a process
				else if (strcmp(cmd, "kill") == 0)
				{
					// printf("Process killed successfullly, pid: %s\n", arg1);
					killProcess(arg1);
				}
				else if (strcmp(cmd, "mkpro") == 0)
				{
					makeProcess(arg1);
				}
				/* show help message */
				else if (strcmp(cmd, "help") == 0)
				{
					help();
				}
				/* create a file */
				else if (strcmp(cmd, "mkfile") == 0)
				{
					if (arg1[0] == '#')
					{
						printf("Irregular filename!");
						continue;
					}

					strcpy(filepath, location);
					getFilepath(filepath, arg1);
					printf("%s  %s\n", arg1, arg2);
					createFile(filepath, arg1, arg2);
					memset(filepath, 0, MAX_FILENAME_LEN);
				}
				/* create a dir */
				else if (strcmp(cmd, "mkdir") == 0)
				{
					if (arg1[0] == '#')
					{
						printf("Irregular dirname!");
						continue;
					}

					strcpy(filepath, location);
					getDirFilepath(filepath, arg1);
					createDir(filepath, arg1);
					memset(filepath, 0, MAX_FILENAME_LEN);
				}
				/* read a file */
				else if (strcmp(cmd, "veri") == 0)
				{
					if (arg1[0] == '#')
					{
						printf("Irregular filename!");
						continue;
					}
					integration(arg1);
					memset(filepath, 0, MAX_FILENAME_LEN);
				}
				else if (strcmp(cmd, "veri2") == 0)

				{

					if (arg1[0] == '#')

					{

						printf("Irregular filename!");

						continue;

					}

					int value = integration2(arg1);

					memset(filepath, 0, MAX_FILENAME_LEN);

				}
				/* read a file */
				else if (strcmp(cmd, "read") == 0)
				{
					if (arg1[0] == '#')
					{
						printf("Irregular filename!");
						continue;
					}
					readFile(arg1);
					memset(filepath, 0, MAX_FILENAME_LEN);
				}
				/* edit a file cover */
				else if (strcmp(cmd, "edit") == 0)
				{
					if (arg1[0] == '#')
					{
						printf("Irregular filename!");
						continue;
					}
					strcpy(filepath, location);
					getFilepath(filepath, arg1);
					editCover(filepath, arg2);
					memset(filepath, 0, MAX_FILENAME_LEN);
				}
				/* edit a file appand */
				else if (strcmp(cmd, "edit+") == 0)
				{
					if (arg1[0] == '#')
					{
						printf("Irregular filename!");
						continue;
					}
					strcpy(filepath, location);
					getFilepath(filepath, arg1);
					editAppand(filepath, arg2);
					memset(filepath, 0, MAX_FILENAME_LEN);
				}
				/* delete a file */
				else if (strcmp(cmd, "delete") == 0)
				{
					if (arg1[0] == '#')
					{
						printf("Irregular filename!");
						continue;
					}
					strcpy(filepath, location);
					getFilepath(filepath, arg1);
					deleteFile(filepath);
					memset(filepath, 0, MAX_FILENAME_LEN);
				}
				/* delete a directory */
				else if (strcmp(cmd, "deletedir") == 0)
				{
					if (arg1[0] == '#')
					{
						printf("Irregular filename!");
						continue;
					}
					strcpy(filepath, location);
					getDirFilepath(filepath, arg1);
					deleteDir(filepath);
					memset(filepath, 0, MAX_FILENAME_LEN);
				}
				/* ls */
				else if (strcmp(cmd, "ls") == 0)
				{
					ls();
				}
				/* cd */
				else if (strcmp(cmd, "cd") == 0)
				{
					if (arg1[0] == '#')
					{
						printf("Irregular filename!");
						continue;
					}
					else if (strcmp(arg1, "..") == 0)
					{
						cdback();
					}
					else
					{
						cd(arg1);
					}
				}
				else if (strcmp(cmd, "information") == 0)

				{

					information();

				}

				/* print */

				else if (strcmp(cmd, "print") == 0)

				{

					printf("%s\n", arg1);

				}
				else
				{
					printf("Command not found\n");
				}
			}
		}
		else {
			close(fd);
			int pid = fork();
			if (pid != 0) { /* parent */
				int s;
				wait(&s);
			}
			else {	/* child */
				//printf("before %s///\n",argv[0]);
				int value = integration2(argv[0]);
				if (value == 1)	
				{			
					printf("verified pass, execute!\n\n");
					execv(argv[0], argv);
						
				}				
				else printf("modified file, shut down!\n\n");
				//printf("after");
			}
		}
	}

	close(1);
	close(0);
}

/*****************************************************************************
*								Welcome
*****************************************************************************/
void welcome()
{

	printf("=============================================================================\n");
	printf("       ooooo     ooooooo         ooo      oooo     ooo      ooooo    oooooooo\n");
	printf("    oooo  oooo   ooo  oooo      ooooo     ooooo    ooo   ooooo  ooo  ooo     \n");
	printf("   ooo      ooo  ooo   ooo      oo ooo    oooooo   ooo  ooo          ooo     \n");
	printf("   ooo      ooo  oooooooo      oo   ooo   ooo oooo ooo  ooo  oooooo  oooooooo\n");
	printf("   ooo      ooo  ooo oooo     ooooooooo   ooo   oooooo  ooo     ooo  ooo     \n");
	printf("   oooo    oooo  ooo   ooo   ooo     ooo  ooo    ooooo  oooo    ooo  ooo     \n");
	printf("     oooooooo    ooo    ooo ooo      ooo  ooo     oooo    oooooooo   oooooooo\n");
	printf("=============================================================================\n");
	printf("\n\n\n\n\n\n\n\n\n\n\n");
}

/*****************************************************************************
*								Clear
*****************************************************************************/
void clear()
{
	int i = 0;
	for (i = 0; i < 20; i++)
		printf("\n");
}

/*****************************************************************************
*								Quit
*****************************************************************************/
void off()
{
	return 0;
}
// /*****************************************************************************
// *							  Show Process
// *****************************************************************************/
// void showProcess()
// {
// 	int i = 0;
// 	printf("********************************************************************************\n");
// 	printf("        name        |        priority        |        f_flags(0 is runable)        \n");
// 	printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
// 	for (i = 0; i < NR_TASKS + NR_PROCS; i++)
// 	{
// 		printf("        %s                   %d                      %d\n", proc_table[i].name, proc_table[i].priority, proc_table[i].p_flags);
// 	}
// 	printf("********************************************************************************\n");
// }

/*****************************************************************************
*							  Show Process
*****************************************************************************/
void showProcess()
{
	int i = 0;
	printf("********************************************************************************\n");
	printf("     id      |     name      |      priority     |       flags(0 is runable)    \n");
	printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	for (i = 0; i < NR_TASKS + NR_PROCS; i++)
	{
		if(proc_table[i].p_flags == FREE_SLOT) {
			continue;
		}
		// char * newString = formatString(proc_table[i].name);
		// printf("%s\n", newString);
		printf("%s%d%s", 
			"      ",
			i,
			"     ");
		if(i < 10) {
			printf(" ");
		}
		showFormatString(proc_table[i].name);
		printf(" %d%s",
			proc_table[i].priority, 
			"                   ");
		if(proc_table[i].priority < 10) {
			printf(" ");
		}
		printf("%d\n", proc_table[i].p_flags);
	}
	printf("********************************************************************************\n");
}

/*****************************************************************************
*							  kill Process
*****************************************************************************/
void killProcess(char str[])
{
	// call a function str2Int() to transfer char[] to int, defined in klib.c
	int i = str2Int(str);
	// printf("pid is(in INT form: %d\n", i);
	if(i >= NR_TASKS + NR_PROCS || i < 0) {
		printf("Error! Pid %d exceeded the range\n", i);
	}
	else if(i < NR_TASKS) {
		printf("System tasks cannot be killed.\n");
	}
	else if(proc_table[i].priority == 0 || proc_table[i].p_flags == FREE_SLOT) 
	{
		printf("Process with pid = %d not found.\n", i);
	}
	else {
		proc_table[i].priority = 0;
		proc_table[i].p_flags = FREE_SLOT;
		printf("Process with pid = %d is finished.\n", i);	
	}
}

/*****************************************************************************
*							  folk new Process
*****************************************************************************/
void makeProcess(char str[])
{
	int pid = fork();
	int childPID;
	for(int i = 0; i < NR_TASKS + NR_PROCS; i++)
	{
		if(proc_table[i].p_flags == FREE_SLOT)
		{
			childPID = i;
			break;
		}
	}
	if(getSize(str) <= 0) {
		strcpy(str, "Unnamed");
	}
	if (pid != 0) { /* parent */
		childPID = pid;
		int s;
		wait(&s);
	}
	else {	/* child */
		// printf("priority: %d, pid: %d, \n", proc_table[childPID].priority, childPID);
		printf("successfullly make a new process.\n");
		strcpy(proc_table[childPID].name, str);
		proc_table[childPID].p_flags = RECEIVING;
		proc_table[childPID].priority = 5;
	}
	showProcess();
}


/*****************************************************************************
*							Show Help Message
*****************************************************************************/
void help()
{
	printf("===============================================================================\n");
	printf("        name                   |                      function                      \n");
	printf("===============================================================================\n");
	printf("        welcome                |       Welcome the users\n");
	printf("        clear                  |       Clean the screen\n");
	printf("        ls                     |       List all files in current file path\n");
	printf("        help                   |       List all commands\n");
	printf("        proc                   |       List all process's message\n");
	printf("        kill   [id]            |       kill a process with this pid\n");
	printf("        mkpro  [name]          |       folk and start a new process\n");
	printf("        mkdir  [name]          |       Create a directory\n");
	printf("        mkfile [file][str]     |       Create a file\n");
	printf("        read   [file]          |       Read a file\n");
	printf("        delete [file]          |       Delete a file\n");
	printf("        deletedir [file]       |       Delete a directory\n");
	printf("        edit   [file][str]     |       Edit file, cover the content\n");
	printf("        edit+  [file][str]     |       Edit file, appand after the content\n");
	printf("===============================================================================\n");

}

/*****************************************************************************
*								Colorful
*****************************************************************************/
void colorful()
{
	int j = 0;
	for (j = 0; j < 2800; j++) { disp_str(" "); }
	disp_color_str("============================================================================\n", BLUE);
	disp_color_str("    ,----..                                      ,--.\n", GREEN);
	disp_color_str("   /   /   \\  ,-.----.      ,---,              ,--.\'|  ,----..       ,---,.\n", GREEN);
	disp_color_str("  /   .     : \\    /  \\    \'  .\' \\         ,--,:  : | /   /   \\    ,\'  .\' |\n", GREEN);
	disp_color_str(" .   /   ;.  \\;   :    \\  /  ;    \'.    ,`--.\'`|  \' :|   :     : ,---.\'   |\n", GREEN);
	disp_color_str(".   ;   /  ` ;|   | .\\ : :  :       \   |   :  :  | |.   |  ;. / |   |   .\'\n", GREEN);
	disp_color_str(";   |  ; \\ ; |.   : |: | :  |   /\   \  :   |   \\ | :.   ; /--`  :   :  |-,\n", GREEN);
	disp_color_str("|   :  | ; | \'|   |  \\ : |  :  \' ;.   : |   : \'  \'; |;   | ;  __ :   |  ;/|\n", GREEN);
	disp_color_str(".   |  \' \' \' :|   : .  / |  |  ;/  \\   \'   \' ;.    ;|   : |.\' .\'|   :   .\'\n", GREEN);
	disp_color_str("'   ;  \\; /  |;   | |  \\ '  :  | \\  \\ ,\'|   | | \\   |.   | \'_.\' :|   |  |-,\n", GREEN);
	disp_color_str(" \\   \\  \',  / |   | ;\\  \\|  |  \'  \'--\'  \'   : |  ; .\'\'   ; : \\  |\'   :  ;/|\n", GREEN);
	disp_color_str("  ;   :    /  :   \' | \\.\'|  :  :        |   | \'`--\'  \'   | \'/  .\'|   |    \\\n", GREEN);
	disp_color_str("   \\   \\ .\'   :   : :-\'  |  | ,\'        \'   : |      |   :    /  |   :   .\'\n", GREEN);
	disp_color_str("    `---`\n", GREEN);
	disp_color_str("===========================================================================\n", BLUE);
	for (j = 0; j < 300; j++)
		disp_str(" ");
	milli_delay(4000);

}
/*****************************************************************************

*								Information

*****************************************************************************/

void information()

{

	printf(" MEMORYSIZE:%dMB\n", memory_size / (1024 * 1024));

	printf(" STACK_SIZE_TOTAL:%dMB\n", STACK_SIZE_TOTAL / (1024 * 1024));

	printf(" MMBUF_SIZE:%dMB\n", MMBUF_SIZE / (1024 * 1024));

	printf(" FSBUF_SIZE:%dMB\n", FSBUF_SIZE / (1024 * 1024));



}
/*****************************************************************************
*							File System
*****************************************************************************/

/*****************************************************************************
*								Init FS
*****************************************************************************/
void initFS()
{
	int fd = -1, n = 0;
	char bufr[1024];
	char filepath[MAX_FILENAME_LEN];
	char dirpath[MAX_FILENAME_LEN];
	char filename[MAX_FILENAME_LEN];

	memset(filequeue, 0, MAX_FILES);
	memset(dirqueue, 0, MAX_DIRS);

	fd = open("root", O_RDWR);	
	if(fd == -1) {
		fd = open("root", O_CREAT | O_RDWR);	
	}
	close(fd);

	fd = open("root", O_RDWR);
	write(fd, bufr, 1024);
	close(fd);

	/*fd = open("root", O_RDWR);
	n = read(fd, bufr, 1024);
	close(fd);

	int i, k;
	for (i = 0, k = 0; i < n; i++)
	{

		if (bufr[i] != ' ')
		{
			filepath[k] = bufr[i];
			k++;
		}
		else
		{
			while (bufr[i] == ' ')
				i++;

			if (strcmp(filepath, "") == 0)
				continue;

			getDirpathAndFilename(dirpath, filename, filepath);
			if (filename[0] == '#')
			{
				strcpy(dirs[dircount], filepath);
				dirqueue[dircount] = 1;
				dircount++;
			}
			else
			{
				strcpy(dirs[dircount], filepath);
				filequeue[filecount] = 1;
				filecount++;
			}

			fd = open(filepath, O_CREAT | O_RDWR);
			close(fd);

			k = 0;

			if (bufr[i] == 0)
				break;

			i--;
		}
	}*/
}

/*****************************************************************************
*							Identity a Directory
*****************************************************************************/
int isDir(const char * filepath)
{
	int pos = getPosInDirQueue(filepath);
	if (pos != -1)
	{
		return 1;
	}
	return 0;
}

/*****************************************************************************
*                             Get Filepath
*****************************************************************************/
void getFilepath(char *filepath, char * filename)
{
	strjin(filepath, filename, '_');
}

/*****************************************************************************
*                         Get Directory Filepath
*****************************************************************************/
void getDirFilepath(char *filepath, char * filename)
{
	strcat(filepath, "_");
	strjin(filepath, filename, '#');
}

/*****************************************************************************
*                   Get Dirpath And Filename/Dirname From Filepath
*****************************************************************************/
void getDirpathAndFilename(char * dirpath, char * filename, char * filepath)
{

	char str[MAX_FILENAME_LEN];
	int i, k;

	memset(dirpath, 0, MAX_FILENAME_LEN);
	memset(filename, 0, MAX_FILENAME_LEN);

	for (i = 0, k = 0; filepath[i] != 0; i++)
	{
		if (filepath[i] != '_')
		{
			str[k] = filepath[i];
			k++;
		}
		else
		{
			strcat(dirpath, str);
			strcat(dirpath, "_");
			memset(str, 0, MAX_FILENAME_LEN);
			k = 0;
		}
	}
	dirpath[strlen(dirpath) - 1] = 0;
	strcpy(dirpath, dirpath);
	strcpy(filename, str);

}

/*****************************************************************************
*						Get a Free Pos in FileQueue
*****************************************************************************/
int getFreeFilePos()
{
	int i = 0;
	for (i = 0; i < MAX_FILES; i++)
	{
		if (filequeue[i] == 0)
			return i;
	}
	printf("The number of files is full!!\n");
	return -1;
}

/*****************************************************************************
*						Get a Free Pos in DirQueue
*****************************************************************************/
int getFreeDirPos()
{
	int i = 0;
	for (i = 0; i < MAX_DIRS; i++)
	{
		if (dirqueue[i] == 0)
			return i;
	}
	printf("The number of folders is full!!\n");
	return -1;
}

/*****************************************************************************
*						Get Dir's Pos in FileQueue
*****************************************************************************/
int getPosInDirQueue(char * filepath)
{
	int i = 0;
	for (i = 0; i < MAX_FILES; i++)
	{
		if (strcmp(dirs[i], filepath) == 0)
			return i;
	}
	return -1;
}


/*****************************************************************************
*						Add Filename Into Dir
*****************************************************************************/
void addFileIntoDir(const char * dirpath, char * filename)
{
	int fd = -1;

	if (strcmp(dirpath, "root") == 0)
	{
		fd = open("root", O_RDWR);
		
	}
	else
	{
		fd = open(dirpath, O_RDWR);
	}

	if (fd == -1)
	{
		printf("%s has not been found!\n", dirpath);
		return;
	}

	strcat(filename, " ");
	editAppand(dirpath, filename);
}

/*****************************************************************************
*						Delete Filename From Dir
*****************************************************************************/
void deleteFileFromDir(const char * dirpath, char * filename)
{

	/*char bufr[MAX_USER_FILE * MAX_FILENAME_LEN];
	char bufw[MAX_USER_FILE * MAX_FILENAME_LEN];*/
	char bufr[1024];
	char bufw[1024];
	char buf[MAX_FILENAME_LEN];
	int fd = -1, n = 0;

	fd = open(dirpath, O_RDWR);

	if (fd == -1)
	{
		printf("%s has not been found!!\n", dirpath);
		return;
	}

	n = read(fd, bufr, 1024);

	int i, k;
	for (i = 0, k = 0; i < n; i++)
	{
		if (bufr[i] != ' ')
		{
			buf[k] = bufr[i];
			k++;
		}
		else
		{
			buf[k] = 0;
			k = 0;

			if (strcmp(buf, filename) == 0)
				continue;

			strcat(bufw, buf);
			strcat(bufw, " ");
		}
	}
	printf("%s\n", bufw);
	
	editCover(dirpath, bufw);

	close(fd);
}

/*****************************************************************************
*							 Create File
*****************************************************************************/
void createFile(char * filepath, char *filename, char * buf)
{
	int fd = -1, pos = -1;
	
	fd = open(filepath, O_CREAT | O_RDWR);
	printf("file name: %s\n content: %s\n", filename, buf);
	if (fd == -1)
	{
		printf("New file failed. Please check and try again!!\n");
		return;
	}
	else if (fd == -2)
	{
		printf("File already exist!!\n");
		return;
	}

	write(fd, buf, strlen(buf));
	close(fd);

	pos = getFreeFilePos();
	filequeue[pos] = 1;
	strcpy(files[pos], filepath);
	filecount++;

	addFileIntoDir(location, filename);
}

/*****************************************************************************
*							 Create Directory
*****************************************************************************/
void createDir(char * filepath, char *filename)
{
	int fd = -1, pos = -1;

	fd = open(filepath, O_CREAT | O_RDWR);
	printf("Folder name: %s\n", filename);
	if (fd == -1)
	{
		printf("New folder failed. Please check and try again!!\n");
		return;
	}
	else if (fd == -2)
	{
		printf("Folder already exists!!\n");
		return;
	}

	close(fd);

	pos = getFreeDirPos();
	dirqueue[pos] = 1;
	strcpy(dirs[pos], filepath);
	dircount++;


	char str[MAX_FILENAME_LEN] = "#";
	strcat(str, filename);
	addFileIntoDir(location, str);
}

/*****************************************************************************
*								integration
*****************************************************************************/
void integration(char * filename)
{
	char filepath[MAX_FILENAME_LEN];
	strcpy(filepath, location);
	getDirFilepath(filepath, filename);
	if (isDir(filepath))
	{
		printf("Cannot read folder!!\n");
		return;
	}
	int fd = -1;
	int n;
	char bufr[1024] = "";
	strcpy(filepath, location);
	getFilepath(filepath, filename);
printf("%s\n", filepath);
	fd = open(filepath, O_RDWR);
	if (fd == -1)
	{
		printf("Opening file error. Please check and try again!\n");
		return;
	}

	n = read(fd, bufr, 1024);
	bufr[n] = 0;
	printf("%s(fd=%d) : %s\n", filepath, fd, bufr);
	close(fd);

	int m = 0, k = 0;
	int i, j;
	for (i = 0; i < n; i++)
	{
		int num = bufr[i];
		m += bufr[i];
		int a, b = num;
		int sum = 0;
		for (j = 0; j < 8; j++)
		{
			a = b % 2;
			b = b / 2;
			sum += a;
		}
		k += sum;
	}
	printf("%d\n", m);
	printf("%d\n", k);
	
		

}
/*****************************************************************************
*								Read File
*****************************************************************************/
void readFile(char * filename)
{
	char filepath[MAX_FILENAME_LEN];
	strcpy(filepath, location);
	getDirFilepath(filepath, filename);
	if (isDir(filepath))
	{
		printf("Cannot read folder!!\n");
		return;
	}

	int fd = -1;
	int n;
	char bufr[1024] = "";

	strcpy(filepath, location);
	getFilepath(filepath, filename);
	fd = open(filepath, O_RDWR);
	if (fd == -1)
	{
		printf("Opening file error. Please check and try again!\n");
		return;
	}

	n = read(fd, bufr, 1024);
	bufr[n] = 0;
	printf("%s(fd=%d) : %s\n", filepath, fd, bufr);
	close(fd);
}

/*****************************************************************************
*							Edit File Cover
*****************************************************************************/
void editCover(const char * filepath, char * str)
{
	char empty[1024];
	int fd = -1;
	fd = open(filepath, O_RDWR);
	if (fd == -1)
	{

		printf("Opening file error. Please check and try again!!\n");
		return;
	}
	memset(empty, 0, 1024);
	write(fd, empty, 1024);
	close(fd);
	fd = open(filepath, O_RDWR);
	write(fd, str, strlen(str));
	close(fd);
}

/*****************************************************************************
*							Edit File Appand
*****************************************************************************/
void editAppand(const char * filepath, char * str)
{
	int fd = -1;
	char bufr[1024];
	char empty[1024];

	fd = open(filepath, O_RDWR);
	if (fd == -1)
	{
		printf("Opening file error. Please check and try again!!\n");
		return;
	}

	read(fd, bufr, 1024);
	close(fd);

	fd = open(filepath, O_RDWR);
	write(fd, empty, 1024);
	close(fd);

	strcat(bufr, str);

	fd = open(filepath, O_RDWR);
	write(fd, bufr, strlen(bufr));
	close(fd);
}
/*****************************************************************************
*							   Delete File
*****************************************************************************/
void deleteFile(char * filepath)
{
	if (filecount == 0)
	{
		printf("Error, no file to delete!\n");
		return;
	}

	if (unlink(filepath) != 0)
	{
		printf("Deleting file error. Please check and try again!\n");
		return;
	}

	int i;
	for (i = 0; i < filecount; i++)
	{
		if (strcmp(files[i], filepath) == 0)
		{
			memset(files[i], 0, MAX_FILENAME_LEN);
			filequeue[i] = 0;
			filecount--;
			break;
		}
	}

	/* delete filename from user's dir */
	char dirpath[MAX_FILENAME_LEN];
	char filename[MAX_FILENAME_LEN];
	getDirpathAndFilename(dirpath, filename, filepath);

	deleteFileFromDir(dirpath, filename);
}

/*****************************************************************************
*							 Delete Directory
*****************************************************************************/
void deleteDir(char * filepath)
{
	if (dircount == 0)
	{
		printf("Error, no folder to delete!!\n");
		return;
	}

	char dirfile[MAX_FILENAME_LEN];
	char rdbuf[1024];
	int fd = -1, n = 0;
	char filename[MAX_FILENAME_LEN];
	fd = open(filepath, O_RDWR);
	if (fd == -1)
	{
		printf("Deleting folder error. Please check and try again!!\n");
		return;
	}

	n = read(fd, rdbuf, 1024);

	int i, k;
	for (i = 0, k = 0; i < n; i++)
	{

		if (rdbuf[i] != ' ')
		{
			dirfile[k] = rdbuf[i];
			k++;
		}
		else
		{
			dirfile[k] = 0;
			k = 0;

			char path[MAX_FILENAME_LEN];
			strcpy(path, filepath);
			strjin(path, filename, '_');

			if (dirfile[0] == '#')
			{
				deleteDir(path);
			}
			else
			{
				deleteFile(path);
			}
		}
	}
	close(fd);

	if (unlink(filepath) != 0)
	{
		printf("Deleting folder error. Please check and try again!\n");
		return;
	}

	for (i = 0; i < dircount; i++)
	{
		if (strcmp(dirs[i], filepath) == 0)
		{
			memset(dirs[i], 0, MAX_FILENAME_LEN);
			dirqueue[i] = 0;
			dircount++;
			break;
		}
	}

	char dirpath[MAX_FILENAME_LEN];

	getDirpathAndFilename(dirpath, filename, filepath);
	deleteFileFromDir(dirpath, filename);
}

/*****************************************************************************
*						List All Files in the Directory
*****************************************************************************/
void ls()
{
	int fd = -1;
	char bufr[1024];

	fd = open(location, O_RDWR);

	if (fd == -1)
	{
		printf("Error opening file\n");
		return;
	}

	read(fd, bufr, 1024);
	printf("%s\n", bufr);
	close(fd);
}

/*****************************************************************************
*									cd
*****************************************************************************/
void cd(char * dirname)
{
	char filepath[MAX_FILENAME_LEN];
	strcpy(filepath, location);
	getDirFilepath(filepath, dirname);
	if (!isDir(filepath))
	{
		printf("NO folder %s!\n", dirname);
		return;
	}

	strcat(location, "_");
	strcat(location, dirname);
}

/*****************************************************************************
*							Go Back To Previous Directory
*****************************************************************************/
void cdback()
{
	if (strcmp(location, "root") == 0)
	{
		printf("ROOT");
		return;
	}

	char dirpath[MAX_FILENAME_LEN];
	char filename[MAX_FILENAME_LEN];

	getDirpathAndFilename(dirpath, filename, location);
	strcpy(location, dirpath);
}

/*****************************************************************************
*									MD5
*****************************************************************************/
void MD5(int size, char * input);
//char resu[33] = {'0'};
//resu[32] = '\0';
int integration2(char * filename)
{
	char filepath[MAX_FILENAME_LEN];
	strcpy(filepath, location);
	getDirFilepath(filepath, filename);
	if (isDir(filepath))
	{
		printf("Cannot read folder!!\n");
		return;
	}
	int fd = -1;
	int n;
	
	//strcpy(filepath, location);
	//getFilepath(filepath, filename);
	fd = open(filename, O_RDWR);
	if (fd == -1)
	{
		printf("Opening file error. Please check and try again!\n");
		return;
	}
	struct stat s;
	int rt = stat(filename, &s);
	char bufr[s.st_size +1];
	n = read(fd, bufr, s.st_size);
	//printf("n:%d", n);
	bufr[n] = 0;
	//printf("%s\n", bufr);
	close(fd);
	//int len = strlen(bufr);
	//printf("%d", len);
	printf("size:%d\n", s.st_size);	
	int m = 0, k = 0;
	int i, j;
	for (i = 0; i < n; i++)
	{
		int num = bufr[i];
		m += bufr[i];
		int a, b = num;
		int sum = 0;
		for (j = 0; j < 8; j++)
		{
			a = b % 2;
			b = b / 2;
			sum += a;
		}
		k += sum;
	}
	printf("Sum check:%d\n", m);
	printf("Parity check:%d\n", k);
	printf("MD5 check:\n", k);
	MD5(50, bufr);
//printf("%s\n", resu);
	int value = panduan(filename);
	return value;
		

}


 
/*各函数声明*/
void shizhuaner(int in, int n, int *md5);
void shizhuaner_weishu(int in, int *md5);
void shiliuzhuaner(char *t, int *temp);
void c_out(int *a, int st);
void abcd_out(int *a);
void F(int *b, int *c, int *d, int *temp1, int *temp2);
void G(int *b, int *c, int *d, int *temp1, int *temp2);
void H(int *b, int *c, int *d, int *temp);
void I(int *b, int *c, int *d, int *temp);
void yu(int *a, int *b, int *temp);
void huo(int *a, int *b, int *temp);
void fei(int *a, int *temp);
void yihuo(int *a, int *b, int *temp);
void jia(int *a, int *b, int *temp);
 
/*十进制转二进制函数*/
void shizhuaner(int in, int n, int *md5)
{
	int j, s, w;  
	s = n / 4 + 1;  //s是md5里面组的排位数，w是该组里面的位数
	w = n % 4;
	j = 1;
	do
	{
		md5[32 * s - 8 * w - j] = in % 2;
		in = in / 2;
		j++;
	} while (in != 0);
	while (j <=8)  //二进制不够八位时补零
	{
		md5[32 * s - 8 * w - j] = 0;
		j++;
	}
}
 
/* 位数填充时所用到的十进制转二进制函数 */
void shizhuaner_weishu(int in, int *md5)
{
	int i,j,temp, a[64];
	for (i = 0; in!= 0; i++)
	{
		a[i] = in % 2;
		in = in / 2;
	}
	while (i % 8 != 0)  //二进制位数不够八的整数倍时补零
	{
		a[i] = 0;
		i++;
	}
	for (j = 0; j <i/2; j++)
	{
		temp = a[i - j - 1];
		a[i - j-1] = a[j];
		a[j] = temp;
		
	}
	temp = i/8;
	for (i=i-1; i < 64; i++)
		a[i] = 0;
	for (i = 0; i < 4; i++) 
	{
		for (j = 0; j < 8; j++)
			md5[512 - temp * 8 + j - 32] = a[i * 8 + j];
		temp = temp - 1;
	}
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 8; j++)
			md5[512 - (i + 1) * 8 + j ] = a[i * 8 + j+32];
	}
}
 
/* 十六进制转二进制函数 */
void shiliuzhuaner(char *t, int *temp)
{
	int i;
	for (i = 0; i < 8; i++)
	{
		switch (t[i])
		{
		case '0':{temp[4 * i] = 0; temp[4 * i + 1] = 0; temp[4 * i + 2] = 0; temp[4 * i + 3] = 0; }break;
		case '1':{temp[4 * i] = 0; temp[4 * i + 1] = 0; temp[4 * i + 2] = 0; temp[4 * i + 3] = 1; }break;
		case '2':{temp[4 * i] = 0; temp[4 * i + 1] = 0; temp[4 * i + 2] = 1; temp[4 * i + 3] = 0; }break;
		case '3':{temp[4 * i] = 0; temp[4 * i + 1] = 0; temp[4 * i + 2] = 1; temp[4 * i + 3] = 1; }break;
		case '4':{temp[4 * i] = 0; temp[4 * i + 1] = 1; temp[4 * i + 2] = 0; temp[4 * i + 3] = 0; }break;
		case '5':{temp[4 * i] = 0; temp[4 * i + 1] = 1; temp[4 * i + 2] = 0; temp[4 * i + 3] = 1; }break;
		case '6':{temp[4 * i] = 0; temp[4 * i + 1] = 1; temp[4 * i + 2] = 1; temp[4 * i + 3] = 0; }break; 
		case '7':{temp[4 * i] = 0; temp[4 * i + 1] = 1; temp[4 * i + 2] = 1; temp[4 * i + 3] = 1; }break;
		case '8':{temp[4 * i] = 1; temp[4 * i + 1] = 0; temp[4 * i + 2] = 0; temp[4 * i + 3] = 0; }break;
		case '9':{temp[4 * i] = 1; temp[4 * i + 1] = 0; temp[4 * i + 2] = 0; temp[4 * i + 3] = 1; }break;
		case 'a':{temp[4 * i] = 1; temp[4 * i + 1] = 0; temp[4 * i + 2] = 1; temp[4 * i + 3] = 0; }break;
		case 'b':{temp[4 * i] = 1; temp[4 * i + 1] = 0; temp[4 * i + 2] = 1; temp[4 * i + 3] = 1; }break;
		case 'c':{temp[4 * i] = 1; temp[4 * i + 1] = 1; temp[4 * i + 2] = 0; temp[4 * i + 3] = 0; }break;
		case 'd':{temp[4 * i] = 1; temp[4 * i + 1] = 1; temp[4 * i + 2] = 0; temp[4 * i + 3] = 1; }break;
		case 'e':{temp[4 * i] = 1; temp[4 * i + 1] = 1; temp[4 * i + 2] = 1; temp[4 * i + 3] = 0; }break;
		case 'f':{temp[4 * i] = 1; temp[4 * i + 1] = 1; temp[4 * i + 2] = 1; temp[4 * i + 3] = 1; }break;	
		}
	}
}
 
/* 密文输出函数 */
void c_out(int *a, int st)
{
	//char resu[9] = {'0'};	
	int i,add;
	for (i = 1; i <= 4; i++)  //二进制转换成十六进制输出
	{
		add = a[32 - i * 8] * 8 + a[32 - i * 8 + 1] * 4 + a[32 - i * 8 + 2] * 2 + a[32 - i * 8 + 3];
		if (add >= 10)
		{
			switch (add)
			{
			case 10: resu[2*i-2 + st] = 'a'; break;
			case 11: resu[2*i-2 + st] = 'b'; break;
			case 12: resu[2*i-2 + st] = 'c'; break;
			case 13: resu[2*i-2 + st] = 'd'; break;
			case 14: resu[2*i-2 + st] = 'e'; break;
			case 15: resu[2*i-2 + st] = 'f'; break;
			}
		}
		else
		{
			//printf("%d", add);
			resu[2*i-2 + st] = add + '0';
		}
		add = a[32 - i * 8+4] * 8 + a[32 - i * 8 + 5] * 4 + a[32 - i * 8 + 6] * 2 + a[32 - i * 8 + 7];
		if (add >= 10)
		{
			switch (add)
			{
			case 10: resu[2*i-1 + st] = 'a'; break;
			case 11: resu[2*i-1 + st] = 'b'; break;
			case 12: resu[2*i-1 + st] = 'c'; break;
			case 13: resu[2*i-1 + st] = 'd'; break;
			case 14: resu[2*i-1 + st] = 'e'; break;
			case 15: resu[2*i-1 + st] = 'f'; break;
			}
		}
		else
		{
			//printf("%d", add);
			resu[2*i-1 + st] = add + '0';
		}
	}

//for (i=0;i<32;i++) printf("%c",resu[i]);
//printf("\n");
	return 0;
}
 
/* 中间过程的输出函数 */
void abcd_out(int *a)
{
	int i, add;
	for (i = 0; i < 4; i++)  //二进制转换成十六进制输出
	{
		add = a[i * 8] * 8 + a[i * 8 + 1] * 4 + a[i * 8 + 2] * 2 + a[i * 8 + 3];
		if (add >= 10)
		{
			switch (add)
			{
			case 10:printf("a"); break;
			case 11:printf("b"); break;
			case 12:printf("c"); break;
			case 13:printf("d"); break;
			case 14:printf("e"); break;
			case 15:printf("f"); break;
			}
		}
		else
			printf("%d", add);
		add = a[i * 8 + 4] * 8 + a[i * 8 + 5] * 4 + a[i * 8 + 6] * 2 + a[i * 8 + 7];
		if (add >= 10)
		{
			switch (add)
			{
			case 10:printf("a"); break;
			case 11:printf("b"); break;
			case 12:printf("c"); break;
			case 13:printf("d"); break;
			case 14:printf("e"); break;
			case 15:printf("f"); break;
			}
		}
		else
			printf("%d", add);
	}
}
 
/* 与函数 */
void yu(int *a, int *b,int *temp)
{
	int i;
	for (i = 0; i < 32; i++)  //同为1为1，否则为0
	{
		if (a[i] == 1 && b[i] == 1)
			temp[i] = 1;
		else
			temp[i] = 0;
	}
}
 
/* 或函数 */
void huo(int *a, int *b, int *temp)
{
	int i;
	for (i = 0; i < 32; i++)  //同0为0，否则为1
	{
		if (a[i] == 0 && b[i] == 0)
			temp[i] = 0;
		else
			temp[i] = 1;
	}
}
 
/* 非函数 */
void fei(int *a, int *temp)
{
	int i;
	for (i = 0; i < 32; i++)  
	{
		if (a[i] == 0)
			temp[i] = 1;
		else
			temp[i] = 0;
	}
}
 
/*异或函数*/
void yihuo(int *a, int *b, int *temp)
{
	int i;
	for (i = 0; i < 32; i++)  //相同为0，不同为1
	{
		if (a[i] != b[i])
			temp[i] = 1;
		else
			temp[i] = 0;
	}
}
 
/* 模二的32次加 */
void jia(int *a, int *b, int *temp)
{
	int i,jin;
	jin = 0;
	for (i = 0; i < 32; i++)
	{
		if (a[31 - i] + b[31 - i] + jin>1)
		{
			temp[31 - i] = a[31 - i] + b[31 - i] + jin - 2;
			jin = 1;
		}
		else
		{
			temp[31 - i] = a[31 - i] + b[31 - i]+jin;
			jin = 0;
		}
	}
}
 
/* F函数 */
void F(int *b, int *c, int *d,int *temp1,int *temp2)
{
	/* F(x,y,z)=(x∧y)∨(¬x∧z) */
	yu(b, c, temp1);
	fei(b, temp2);
	yu(temp2, d, temp2);
	huo(temp1, temp2, temp2);
}
 
/* G函数 */
void G(int *b, int *c, int *d, int *temp1, int *temp2)
{
	/* G(x,y,z)=(x∧z)∨(y∧¬z) */
	yu(b, d, temp1);
	fei(d, temp2);
	yu(temp2, c, temp2);
	huo(temp1, temp2, temp2);
}
 
/* H函数 */
void H(int *b, int *c, int *d, int *temp)
{
	/* H(x,y,z)=x⊕y⊕z */
	yihuo(b, c, temp);
	yihuo(temp, d, temp);
}
 
/* I函数 */
void I(int *b, int *c, int *d, int *temp)
{
	/* I(x,y,z)=y⊕(x∨¬z) */
	fei(d, temp);
	huo(b, temp, temp);
	yihuo(c, temp, temp);
}
 
/*左移函数*/
void move(int step, int *temp1, int *temp2)
{
	int i;
	for (i = 0; i < 32 - step; i++)
		temp2[i] = temp1[i + step];
	for (i = 0; i < step; i++)
		temp2[32 - step + i] = temp1[i];
}
 
/*每一大轮的16小轮循环函数*/
void round16(int *a, int *b, int *c, int *d, int *m, int *md5, int r, char *t1, 
	char *t2, char *t3, char *t4, char *t5, char *t6, char *t7, char *t8, char *t9, 
	char *t10, char *t11, char *t12, char *t13, char *t14, char *t15, char *t16 )
{
	int i, j, in, step , temp1[32], temp2[32];
	for (i = 0; i < 16; i++)
	{
		switch (r)  //根据r判断所选的逻辑函数
		{
		case 1:F(b, c, d, temp1, temp2); break;
		case 2:G(b, c, d, temp1, temp2); break;
		case 3:H(b, c, d, temp2); break;
		case 4:I(b, c, d, temp2); break;
		}
		in = m[i];
		for (j = 0; j < 32; j++)
			temp1[j] = md5[in * 32 + j];
		jia(temp2, temp1, temp2);
		switch (i + 1)  //选择t[]
		{
		case 1:shiliuzhuaner(t1, temp1); break;
		case 2:shiliuzhuaner(t2, temp1); break;
		case 3:shiliuzhuaner(t3, temp1); break;
		case 4:shiliuzhuaner(t4, temp1); break;
		case 5:shiliuzhuaner(t5, temp1); break;
		case 6:shiliuzhuaner(t6, temp1); break;
		case 7:shiliuzhuaner(t7, temp1); break;
		case 8:shiliuzhuaner(t8, temp1); break;
		case 9:shiliuzhuaner(t9, temp1); break;
		case 10:shiliuzhuaner(t10, temp1); break;
		case 11:shiliuzhuaner(t11, temp1); break;
		case 12:shiliuzhuaner(t12, temp1); break;
		case 13:shiliuzhuaner(t13, temp1); break;
		case 14:shiliuzhuaner(t14, temp1); break;
		case 15:shiliuzhuaner(t15, temp1); break;
		case 16:shiliuzhuaner(t16, temp1); break;
		}
		jia(temp2, temp1, temp2);
		jia(temp2, a, temp2);
		switch(r)  //根据r为左移步数step赋值
		{  
		case 1:switch (i % 4 + 1){ case 1:step = 7; break; case 2:step = 12; break; case 3:step = 17; break; case 4:step = 22; break; }break;
		case 2:switch (i % 4 + 1){ case 1:step = 5; break; case 2:step = 9; break; case 3:step = 14; break; case 4:step = 20; break; }break;
		case 3:switch (i % 4 + 1){ case 1:step = 4; break; case 2:step = 11; break; case 3:step = 16; break; case 4:step = 23; break; }break;
		case 4:switch (i % 4 + 1){ case 1:step = 6; break; case 2:step = 10; break; case 3:step = 15; break; case 4:step = 21; break; }break;
		}
		move(step, temp2, temp1);
		jia(temp1, b, temp2);
		for (j = 0; j < 32; j++)
		{
			a[j] = d[j];
			d[j] = c[j];
			c[j] = b[j];
			b[j] = temp2[j];
		}
 
		//*若想输出每轮a、b、c、d的值，把下面的注释取消即可
		/*printf("第%d大轮的第%d小轮\n", r, i);
		abcd_out(a);
		printf("   ");
		abcd_out(b);
		printf("   ");
		abcd_out(c);
		printf("   ");
		abcd_out(d);
		printf("\n");*/
 
	}
}
 
/* 主函数 */
void MD5(int size, char * input)
{
	
		
	char ch,
		/* 一大坨t[] */
		t1[8] = { 'd', '7', '6', 'a', 'a', '4', '7', '8' },
		t2[8] = { 'e', '8', 'c', '7', 'b', '7', '5', '6' },
		t3[8] = { '2', '4', '2', '0', '7', '0', 'd', 'b' },
		t4[8] = { 'c', '1', 'b', 'd', 'c', 'e', 'e', 'e' },
		t5[8] = { 'f', '5', '7', 'c', '0', 'f', 'a', 'f' },
		t6[8] = { '4', '7', '8', '7', 'c', '6', '2', 'a' },
		t7[8] = { 'a', '8', '3', '0', '4', '6', '1', '3' },
		t8[8] = { 'f', 'd', '4', '6', '9', '5', '0', '1' },
		t9[8] = { '6', '9', '8', '0', '9', '8', 'd', '8' },
		t10[8] = { '8', 'b', '4', '4', 'f', '7', 'a', 'f' },
		t11[8] = { 'f', 'f', 'f', 'f', '5', 'b', 'b', '1' },
		t12[8] = { '8', '9', '5', 'c', 'd', '7', 'b', 'e' },
		t13[8] = { '6', 'b', '9', '0', '1', '1', '2', '2' },
		t14[8] = { 'f', 'd', '9', '8', '7', '1', '9', '3' },
		t15[8] = { 'a', '6', '7', '9', '4', '3', '8', 'e' },
		t16[8] = { '4', '9', 'b', '4', '0', '8', '2', '1' },
		t17[8] = { 'f', '6', '1', 'e', '2', '5', '6', '2' },
		t18[8] = { 'c', '0', '4', '0', 'b', '3', '4', '0' },
		t19[8] = { '2', '6', '5', 'e', '5', 'a', '5', '1' },
		t20[8] = { 'e', '9', 'b', '6', 'c', '7', 'a', 'a' },
		t21[8] = { 'd', '6', '2', 'f', '1', '0', '5', 'd' },
		t22[8] = { '0', '2', '4', '4', '1', '4', '5', '3' },
		t23[8] = { 'd', '8', 'a', '1', 'e', '6', '8', '1' },
		t24[8] = { 'e', '7', 'd', '3', 'f', 'b', 'c', '8' },
		t25[8] = { '2', '1', 'e', '1', 'c', 'd', 'e', '6' },
		t26[8] = { 'c', '3', '3', '7', '0', '7', 'd', '6' },
		t27[8] = { 'f', '4', 'd', '5', '0', 'd', '8', '7' },
		t28[8] = { '4', '5', '5', 'a', '1', '4', 'e', 'd' },
		t29[8] = { 'a', '9', 'e', '3', 'e', '9', '0', '5' },
		t30[8] = { 'f', 'c', 'e', 'f', 'a', '3', 'f', '8' },
		t31[8] = { '6', '7', '6', 'f', '0', '2', 'd', '9' },
		t32[8] = { '8', 'd', '2', 'a', '4', 'c', '8', 'a' },
		t33[8] = { 'f', 'f', 'f', 'a', '3', '9', '4', '2' },
		t34[8] = { '8', '7', '7', '1', 'f', '6', '8', '1' },
		t35[8] = { '6', 'd', '9', 'd', '6', '1', '2', '2' },
		t36[8] = { 'f', 'd', 'e', '5', '3', '8', '0', 'c' },
		t37[8] = { 'a', '4', 'b', 'e', 'e', 'a', '4', '4' },
		t38[8] = { '4', 'b', 'd', 'e', 'c', 'f', 'a', '9' },
		t39[8] = { 'f', '6', 'b', 'b', '4', 'b', '6', '0' },
		t40[8] = { 'b', 'e', 'b', 'f', 'b', 'c', '7', '0' },
		t41[8] = { '2', '8', '9', 'b', '7', 'e', 'c', '6' },
		t42[8] = { 'e', 'a', 'a', '1', '2', '7', 'f', 'a' },
		t43[8] = { 'd', '4', 'e', 'f', '3', '0', '8', '5' },
		t44[8] = { '0', '4', '8', '8', '1', 'd', '0', '5' },
		t45[8] = { 'd', '9', 'd', '4', 'd', '0', '3', '9' },
		t46[8] = { 'e', '6', 'd', 'b', '9', '9', 'e', '5' },
		t47[8] = { '1', 'f', 'a', '2', '7', 'c', 'f', '8' },
		t48[8] = { 'c', '4', 'a', 'c', '5', '6', '6', '5' },
		t49[8] = { 'f', '4', '2', '9', '2', '2', '4', '4' },
		t50[8] = { '4', '3', '2', 'a', 'f', 'f', '9', '7' },
		t51[8] = { 'a', 'b', '9', '4', '2', '3', 'a', '7' },
		t52[8] = { 'f', 'c', '9', '3', 'a', '0', '3', '9' },
		t53[8] = { '6', '5', '5', 'b', '5', '9', 'c', '3' },
		t54[8] = { '8', 'f', '0', 'c', 'c', 'c', '9', '2' },
		t55[8] = { 'f', 'f', 'e', 'f', 'f', '4', '7', 'd' },
		t56[8] = { '8', '5', '8', '4', '5', 'd', 'd', '1' },
		t57[8] = { '6', 'f', 'a', '8', '7', 'e', '4', 'f' },
		t58[8] = { 'f', 'e', '2', 'c', 'e', '6', 'e', '0' },
		t59[8] = { 'a', '3', '0', '1', '4', '3', '1', '4' },
		t60[8] = { '4', 'e', '0', '8', '1', '1', 'a', '1' },
		t61[8] = { 'f', '7', '5', '3', '7', 'e', '8', '2' },
		t62[8] = { 'b', 'd', '3', 'a', 'f', '2', '3', '5' },
		t63[8] = { '2', 'a', 'd', '7', 'd', '2', 'b', 'b' },
		t64[8] = { 'e', 'b', '8', '6', 'd', '3', '9', '1' };
	int in, n = 0, i,j,addup;
	int md5[512] = {0},
		/*每一大轮m[]的调用顺序*/
		m1[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		m2[16] = { 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12 },
		m3[16] = { 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2 },
		m4[16] = { 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9 },
		/* a[]、b[]、c[]、d[]的初始值(已经过大小端处理) */
		/* 把a[]、b[]、c[]、d[]赋值给a1[]、b1[]、c1[]、d1[]*/
		a[32] = { 0, 1, 1, 0, 0, 1, 1, 1,
		0, 1, 0, 0, 0, 1, 0, 1,
		0, 0, 1, 0, 0, 0, 1, 1,
		0, 0, 0, 0, 0, 0, 0, 1 },
		a1[32] = { 0, 1, 1, 0, 0, 1, 1, 1,
		0, 1, 0, 0, 0, 1, 0, 1,
		0, 0, 1, 0, 0, 0, 1, 1,
		0, 0, 0, 0, 0, 0, 0, 1 },
		b[32] = { 1, 1, 1, 0, 1, 1, 1, 1,
		1, 1, 0, 0, 1, 1, 0, 1,
		1, 0, 1, 0, 1, 0, 1, 1,
		1, 0, 0, 0, 1, 0, 0, 1 },
		b1[32] = { 1, 1, 1, 0, 1, 1, 1, 1,
		1, 1, 0, 0, 1, 1, 0, 1,
		1, 0, 1, 0, 1, 0, 1, 1,
		1, 0, 0, 0, 1, 0, 0, 1 },
		c[32] = { 1, 0, 0, 1, 1, 0, 0, 0,
		1, 0, 1, 1, 1, 0, 1, 0,
		1, 1, 0, 1, 1, 1, 0, 0,
		1, 1, 1, 1, 1, 1, 1, 0 },
		c1[32] = { 1, 0, 0, 1, 1, 0, 0, 0,
		1, 0, 1, 1, 1, 0, 1, 0,
		1, 1, 0, 1, 1, 1, 0, 0,
		1, 1, 1, 1, 1, 1, 1, 0 },
		d[32] = { 0, 0, 0, 1, 0, 0, 0, 0,
		0, 0, 1, 1, 0, 0, 1, 0,
		0, 1, 0, 1, 0, 1, 0, 0,
		0, 1, 1, 1, 0, 1, 1, 0 },
		d1[32] = { 0, 0, 0, 1, 0, 0, 0, 0,
		0, 0, 1, 1, 0, 0, 1, 0,
		0, 1, 0, 1, 0, 1, 0, 0,
		0, 1, 1, 1, 0, 1, 1, 0 };
	
	//printf("%d\n", size);
	for (i = 0; i < size; i++)  //用getchar()函数接收字符，直到接收到回车符或字符数超过56为止
	{
		ch = input[i];	
//printf("%c",ch);	
		in = (int)ch;
//printf("%d", in);		
		shizhuaner(in, n, md5);
		n++;
		
	}
	i = 0;
	addup = n;
	while (n% 4 != 0)  //长度不是4的倍数，补一个1和0直到长度为4的倍数,，最终实现用1与0使其长度模512与448同于，在这个程序里也就是448
	{
		int s, w, j;
		s = n / 4 + 1;
		w = n % 4;
		j = 1;
		do
		{
			md5[32 * s - 8 * w - j] = 0;
			j++;
		} while (j<=7);
		if (i == 0)
		{
			md5[32 * s - 8 * w - j] = 1;  
			i = 1;
		}
		n++;
	}
	if (i == 0)  //长度不是4的倍数，补一个1和31个0
	{
		for (j = 0; j < 32; j++)
			md5[n * 8 + j] = 0;
		md5[8 * n + 24] = 1;
	}
	for (i = 0; i < 512; i++)  //补零，任何不为1的数都设为0
	{
		if (md5[i] == 1)
			md5[i] = 1;
		else
			md5[i] = 0;
	}
	//printf("\n");
    shizhuaner_weishu(addup * 8, md5);  //64位数填充
 
	/*若想看m[0]~m[15],把下面注释去掉即可*/
	/*printf("m[0]~m[15]如下:\n");
	for (i = 0; i < 512; i++)
	{
		printf("%d ", md5[i]);
		if (i % 8 == 7)
			printf("\n");
		if (i % 32 == 31)
			printf("\n");
	}
	printf("\n");*/
 
	/* 第一、二、三、四大轮，每一大轮下有16小轮 */
	round16(a, b, c, d, m1, md5, 1, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16);
	round16(a, b, c, d, m2, md5, 2, t17, t18, t19, t20, t21, t22, t23, t24, t25, t26, t27, t28, t29, t30, t31, t32);
	round16(a, b, c, d, m3, md5, 3, t33, t34, t35, t36, t37, t38, t39, t40, t41, t42, t43, t44, t45, t46, t47, t48);
	round16(a, b, c, d, m4, md5, 4, t49, t50, t51, t52, t53, t54, t55, t56, t57, t58, t59, t60, t61, t62, t63, t64);
	//printf("\n");
	/* 最终的a、b、c、d分别与最初的a、b、c、d相加 */
	jia(a, a1, a);
	jia(b, b1, b);
	jia(c, c1, c);
	jia(d, d1, d);
	/*密文输出*/
	//printf("%s\n",resu);
	c_out(a, 0);
	c_out(b, 8);
	c_out(c, 16);
	c_out(d, 24);
	//char *resu = strcat(strcat(strcat(aa, bb), cc), dd);
	//printf("%s\n", resu);	
	//printf("\n");
	return 0;
}


int panduan(char * filename)
{
	char str[33] = {0};
	memcpy(str, resu, 32);
	printf("  current  value:%s\n",str);
	int value = 0;
	switch(filename[0])
	{
		case 'g':
		{
			//printf("%s\n", md5);	
			printf("  original value:2e371b8b7cfd12c3abdeb103d7aea83b\n");	
			if (strcmp(str, "2e371b8b7cfd12c3a6deb103d7aea83b")== 0)
			{
				value = 1;
				printf("right\n");
			}
			else printf("wrong\n");
			break;
		}
		case 'p':
		{
			//printf("%s\n", md5);	
			printf("  original value:70f2deb1fedde85441e714dc06df0955\n");	
			if (strcmp(str, "70f2deb1fedde85441e714dc06df0955")== 0)
			{
				value = 1;
				printf("right\n");
			}
			else printf("wrong\n");
			break;
		}
		case 'e':
		{
			//printf("%s\n", md5);	
			printf("  original value:4a9eb906014af1d836fb96d8f625c3ae\n");	
			if (strcmp(str, "4a9eb906014af1d836fb96d8f625c3ae")== 0)
			{
				value = 1;
				printf("right\n");
			}
			else printf("wrong\n");
			break;
		}
		case 'c':
		{
			//printf("%s\n", md5);	
			printf("  original value:87fa8d006a2188b96dec503c8532bfea\n");	
			if (strcmp(str, "87fa8d006a2188b96dec503c8532bfea")== 0)
			{
				value = 1;
				printf("right\n");
			}
			else printf("wrong\n");
			break;
		}
	}
	//printf("\n");
	return value;
}

