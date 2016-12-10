#ifndef LINUX_SV_H
#define LINUX_SV_H

#ifdef CONFIG_SELF_VIRTUALIZATION
int virtualize_self(void);
#else
int virtualize_self(void)
{
	return 0;
}
#endif

#endif
