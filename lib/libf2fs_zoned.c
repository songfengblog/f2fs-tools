/**
 * libf2fs_zoned.c
 *
 * Copyright (c) 2016 Western Digital Corporation.
 * Written by: Damien Le Moal <damien.lemoal@wdc.com>
 *
 * Dual licensed under the GPL or LGPL version 2 licenses.
 */
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <f2fs_fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif
#ifdef HAVE_LINUX_LIMITS_H
#include <linux/limits.h>
#endif
#ifndef ANDROID_WINDOWS_HOST
#include <sys/ioctl.h>
#endif
#include <libgen.h>

#include <f2fs_fs.h>

#ifdef HAVE_LINUX_BLKZONED_H

/*
 * Read up to 255 characters from the first line of a file. Strip the trailing
 * newline.
 */
static char *read_file(const char *path)
{
	char line[256], *p = line;
	FILE *f;

	f = fopen(path, "rb");
	if (!f)
		return NULL;
	if (!fgets(line, sizeof(line), f))
		line[0] = '\0';
	strsep(&p, "\n");
	fclose(f);

	return strdup(line);
}

static char *read_sys_attr(const char *dev_path, const char *attr)
{
	struct stat statbuf;
	char *sys_devno_path = NULL;
	char sys_path[PATH_MAX];
	ssize_t sz;
	char *part_attr_path = NULL;
	char *part_str = NULL;
	char *delim = NULL;
	char *attr_path = NULL;
	char *attr_str = NULL;

	if (stat(dev_path, &statbuf) < 0)
		goto out;

	if (asprintf(&sys_devno_path, "/sys/dev/block/%d:%d",
		     major(statbuf.st_rdev), minor(statbuf.st_rdev)) < 0)
		goto out;

	sz = readlink(sys_devno_path, sys_path, sizeof(sys_path) - 1);
	if (sz < 0)
		goto out;
	sys_path[sz] = '\0';

	/*
	 * If the device is a partition device, cut the device name in the
	 * canonical sysfs path to obtain the sysfs path of the holder device.
	 *   e.g.:  /sys/devices/.../sda/sda1 -> /sys/devices/.../sda
	 */
	if (asprintf(&part_attr_path, "/sys/dev/block/%s/partition",
		     sys_path) < 0)
		goto out;
	part_str = read_file(part_attr_path);
	if (part_str && *part_str == '1') {
		delim = strrchr(sys_path, '/');
		if (!delim)
			goto out;
		*delim = '\0';
	}

	if (asprintf(&attr_path, "/sys/dev/block/%s/%s", sys_path, attr) < 0)
		goto out;

	attr_str = read_file(attr_path);
out:
	free(attr_path);
	free(part_str);
	free(part_attr_path);
	free(sys_devno_path);
	return attr_str;
}

int f2fs_get_zoned_model(int i)
{
	struct device_info *dev = c.devices + i;
	char *model_str;

	model_str = read_sys_attr(dev->path, "queue/zoned");
	if (!model_str) {
		/*
		 * The kernel does not support zoned block devices, but we have
		 * a block device file. This means that the device is not zoned
		 * or is zoned but can be randomly written (i.e. host-aware
		 * zoned model). Treat the device as a regular block device.
		 */
		dev->zoned_model = F2FS_ZONED_NONE;
		return 0;
	}

	if (strcmp(model_str, "none") == 0) {
		/* Regular block device */
		dev->zoned_model = F2FS_ZONED_NONE;
	} else if (strcmp(model_str, "host-aware") == 0) {
		/* Host-aware zoned block device: can be randomly written */
		dev->zoned_model = F2FS_ZONED_HA;
	} else if (strcmp(model_str, "host-managed") == 0) {
		/* Host-managed zoned block device: sequential writes needed */
		dev->zoned_model = F2FS_ZONED_HM;
	} else {
		MSG(0, "\tError: Unsupported device zoned model: %s\n",
							model_str);
		free(model_str);
		return -1;
	}
	free(model_str);
	return 0;
}

int f2fs_get_zone_blocks(int i)
{
	struct device_info *dev = c.devices + i;
	uint64_t sectors;
	char * cs_str;

	/* Get zone size */
	dev->zone_blocks = 0;

	cs_str = read_sys_attr(dev->path, "queue/chunk_sectors");
	if (!cs_str)
		return -1;

	sectors = atol(cs_str);
	free(cs_str);
	if (!sectors)
		return -1;

	dev->zone_blocks = sectors >> (F2FS_BLKSIZE_BITS - 9);
	sectors = (sectors << 9) / c.sector_size;

	/*
	 * Total number of zones: there may
	 * be a last smaller runt zone.
	 */
	dev->nr_zones = dev->total_sectors / sectors;
	if (dev->total_sectors % sectors)
		dev->nr_zones++;

	return 0;
}

#define F2FS_REPORT_ZONES_BUFSZ	524288

int f2fs_check_zones(int j)
{
	struct device_info *dev = c.devices + j;
	struct blk_zone_report *rep;
	struct blk_zone *blkz;
	unsigned int i, n = 0;
	u_int64_t total_sectors;
	u_int64_t sector;
	int last_is_conv = 1;
	int ret = -1;

	rep = malloc(F2FS_REPORT_ZONES_BUFSZ);
	if (!rep) {
		ERR_MSG("No memory for report zones\n");
		return -ENOMEM;
	}

	dev->nr_rnd_zones = 0;
	sector = 0;
	total_sectors = (dev->total_sectors * c.sector_size) >> 9;

	while (sector < total_sectors) {

		/* Get zone info */
		memset(rep, 0, F2FS_REPORT_ZONES_BUFSZ);
		rep->sector = sector;
		rep->nr_zones = (F2FS_REPORT_ZONES_BUFSZ - sizeof(struct blk_zone_report))
			/ sizeof(struct blk_zone);

		ret = ioctl(dev->fd, BLKREPORTZONE, rep);
		if (ret != 0) {
			ret = -errno;
			ERR_MSG("ioctl BLKREPORTZONE failed\n");
			goto out;
		}

		if (!rep->nr_zones)
			break;

		blkz = (struct blk_zone *)(rep + 1);
		for (i = 0; i < rep->nr_zones && sector < total_sectors; i++) {

			if (blk_zone_cond(blkz) == BLK_ZONE_COND_READONLY ||
			    blk_zone_cond(blkz) == BLK_ZONE_COND_OFFLINE)
				last_is_conv = 0;
			if (blk_zone_conv(blkz) ||
			    blk_zone_seq_pref(blkz)) {
				if (last_is_conv)
					dev->nr_rnd_zones++;
			} else {
				last_is_conv = 0;
			}

			if (blk_zone_conv(blkz)) {
				DBG(2,
				    "Zone %05u: Conventional, cond 0x%x (%s), sector %llu, %llu sectors\n",
				    n,
				    blk_zone_cond(blkz),
				    blk_zone_cond_str(blkz),
				    blk_zone_sector(blkz),
				    blk_zone_length(blkz));
			} else {
				DBG(2,
				    "Zone %05u: type 0x%x (%s), cond 0x%x (%s), need_reset %d, "
				    "non_seq %d, sector %llu, %llu sectors, wp sector %llu\n",
				    n,
				    blk_zone_type(blkz),
				    blk_zone_type_str(blkz),
				    blk_zone_cond(blkz),
				    blk_zone_cond_str(blkz),
				    blk_zone_need_reset(blkz),
				    blk_zone_non_seq(blkz),
				    blk_zone_sector(blkz),
				    blk_zone_length(blkz),
				    blk_zone_wp_sector(blkz));
			}

			sector = blk_zone_sector(blkz) + blk_zone_length(blkz);
			n++;
			blkz++;
		}
	}

	if (sector != total_sectors) {
		ERR_MSG("Invalid zones: last sector reported is %llu, expected %llu\n",
			(unsigned long long)(sector << 9) / c.sector_size,
			(unsigned long long)dev->total_sectors);
		ret = -1;
		goto out;
	}

	if (n != dev->nr_zones) {
		ERR_MSG("Inconsistent number of zones: expected %u zones, got %u\n",
			dev->nr_zones, n);
		ret = -1;
		goto out;
	}

	/*
	 * For a multi-device volume, fixed position metadata blocks are
	 * stored * only on the first device of the volume. Checking for the
	 * presence of * conventional zones (randomly writeabl zones) for
	 * storing these blocks * on a host-managed device is thus needed only
	 * for the device index 0.
	 */
	if (j == 0 && dev->zoned_model == F2FS_ZONED_HM &&
			!dev->nr_rnd_zones) {
		ERR_MSG("No conventional zone for super block\n");
		ret = -1;
	}
out:
	free(rep);
	return ret;
}

int f2fs_reset_zones(int j)
{
	struct device_info *dev = c.devices + j;
	struct blk_zone_report *rep;
	struct blk_zone *blkz;
	struct blk_zone_range range;
	u_int64_t total_sectors;
	u_int64_t sector;
	unsigned int i;
	int ret = -1;

	rep = malloc(F2FS_REPORT_ZONES_BUFSZ);
	if (!rep) {
		ERR_MSG("No memory for report zones\n");
		return -1;
	}

	sector = 0;
	total_sectors = (dev->total_sectors * c.sector_size) >> 9;
	while (sector < total_sectors) {

		/* Get zone info */
		memset(rep, 0, F2FS_REPORT_ZONES_BUFSZ);
		rep->sector = sector;
		rep->nr_zones = (F2FS_REPORT_ZONES_BUFSZ - sizeof(struct blk_zone_report))
			/ sizeof(struct blk_zone);

		ret = ioctl(dev->fd, BLKREPORTZONE, rep);
		if (ret != 0) {
			ret = -errno;
			ERR_MSG("ioctl BLKREPORTZONES failed\n");
			goto out;
		}

		if (!rep->nr_zones)
			break;

		blkz = (struct blk_zone *)(rep + 1);
		for (i = 0; i < rep->nr_zones && sector < total_sectors; i++) {
			if (blk_zone_seq(blkz) &&
			    !blk_zone_empty(blkz)) {
				/* Non empty sequential zone: reset */
				range.sector = blk_zone_sector(blkz);
				range.nr_sectors = blk_zone_length(blkz);
				ret = ioctl(dev->fd, BLKRESETZONE, &range);
				if (ret != 0) {
					ret = -errno;
					ERR_MSG("ioctl BLKRESETZONE failed\n");
					goto out;
				}
			}
			sector = blk_zone_sector(blkz) + blk_zone_length(blkz);
			blkz++;
		}
	}
out:
	free(rep);
	if (!ret)
		MSG(0, "Info: Discarded %"PRIu64" MB\n", (sector << 9) >> 20);
	return ret;
}

#else

int f2fs_get_zoned_model(int i)
{
	struct device_info *dev = c.devices + i;

	c.zoned_mode = 0;
	dev->zoned_model = F2FS_ZONED_NONE;
	return 0;
}

int f2fs_get_zone_blocks(int i)
{
	struct device_info *dev = c.devices + i;

	c.zoned_mode = 0;
	dev->nr_zones = 0;
	dev->zone_blocks = 0;
	dev->zoned_model = F2FS_ZONED_NONE;

	return 0;
}

int f2fs_check_zones(int i)
{
	ERR_MSG("%d: Zoned block devices are not supported\n", i);
	return -1;
}

int f2fs_reset_zones(int i)
{
	ERR_MSG("%d: Zoned block devices are not supported\n", i);
	return -1;
}

#endif

