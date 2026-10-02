/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************
 *
 * $Id: gpio.c,v 1.15 2010-03-19 07:38:03 steven Exp $
 */

#include <stdio.h>             
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <linux/autoconf.h>
#include "ralink_gpio.h"

#define GPIO_DEV	"/dev/gpio"

enum {
	gpio_in,
	gpio_out,
};
enum {
	gpio2300,
#ifdef RALINK_GPIO_HAS_5124
	gpio3924,
	gpio5140,
#endif
};

int gpio_set_dir(int r, int dir)
{
	int fd, req;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	if (dir == gpio_in) {
#ifdef RALINK_GPIO_HAS_5124
		if (r == gpio5140)
			req = RALINK_GPIO5140_SET_DIR_IN;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_IN;
		else
#endif
			req = RALINK_GPIO_SET_DIR_IN;
	}
	else {
#ifdef RALINK_GPIO_HAS_5124
		if (r == gpio5140)
			req = RALINK_GPIO5140_SET_DIR_OUT;
		else if (r == gpio3924)
			req = RALINK_GPIO3924_SET_DIR_OUT;
		else
#endif
			req = RALINK_GPIO_SET_DIR_OUT;
	}
	if (ioctl(fd, req, 0xffffffff) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_read_int(int r, int *value)
{
	int fd, req;

	*value = 0;
	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}

#ifdef RALINK_GPIO_HAS_5124
	if (r == gpio5140)
		req = RALINK_GPIO5140_READ;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_READ;
	else
#endif
		req = RALINK_GPIO_READ;
	if (ioctl(fd, req, value) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_write_int(int r, int value)
{
	int fd, req;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
#ifdef RALINK_GPIO_HAS_5124
	if (r == gpio5140)
		req = RALINK_GPIO5140_WRITE;
	else if (r == gpio3924)
		req = RALINK_GPIO3924_WRITE;
	else
#endif
		req = RALINK_GPIO_WRITE;
	if (ioctl(fd, req, value) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_enb_irq(void)
{
	int fd;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	if (ioctl(fd, RALINK_GPIO_ENABLE_INTP) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_dis_irq(void)
{
	int fd;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	if (ioctl(fd, RALINK_GPIO_DISABLE_INTP) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_reg_info(int gpio_num)
{
	int fd;
	ralink_gpio_reg_info info;

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	info.pid = getpid();
	info.irq = gpio_num;
	if (ioctl(fd, RALINK_GPIO_REG_IRQ, &info) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}



void gpio_test_write(void)
{
	int i = 0;

	//set gpio direction to output
#ifdef RALINK_GPIO_HAS_5124
	gpio_set_dir(gpio5140, gpio_out);
	gpio_set_dir(gpio3924, gpio_out);
#endif
	gpio_set_dir(gpio2300, gpio_out);

	//turn off LEDs
#ifdef RALINK_GPIO_HAS_5124
	gpio_write_int(gpio5140, 0xffffffff);
	gpio_write_int(gpio3924, 0xffffffff);
#endif
	gpio_write_int(gpio2300, 0xffffffff);
	sleep(3);

	//turn on all LEDs
#ifdef RALINK_GPIO_HAS_5124
	gpio_write_int(gpio5140, 0);
	gpio_write_int(gpio3924, 0);
#endif
	gpio_write_int(gpio2300, 0);
}

void gpio_test_read(void)
{
	int i, d;

#ifdef RALINK_GPIO_HAS_5124
	gpio_set_dir(gpio5140, gpio_in);
	gpio_read_int(gpio5140, &d);
	printf("gpio 51~40 = 0x%x\n", d);

	gpio_set_dir(gpio3924, gpio_in);
	gpio_read_int(gpio3924, &d);
	printf("gpio 39~24 = 0x%x\n", d);
#endif
	gpio_set_dir(gpio2300, gpio_in);
	gpio_read_int(gpio2300, &d);
	printf("gpio 23~00 = 0x%x\n", d);
}

void signal_handler(int signum)
{
	printf("gpio tester: signal ");
	if (signum == SIGUSR1)
		printf("SIGUSR1");
	else if (signum == SIGUSR2)
		printf("SIGUSR2");
	else
		printf("%d", signum);
	printf(" received\n", signum);
}

void gpio_test_intr(int gpio_num)
{
	//set gpio direction to input
#ifdef RALINK_GPIO_HAS_5124
	gpio_set_dir(gpio5140, gpio_in);
	gpio_set_dir(gpio3924, gpio_in);
#endif
	gpio_set_dir(gpio2300, gpio_in);

	//enable gpio interrupt
	gpio_enb_irq();

	//register my information
	gpio_reg_info(gpio_num);

	//issue a handler to handle SIGUSR1
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);

	//wait for signal
	pause();

	//disable gpio interrupt
	gpio_dis_irq();
}

void gpio_set_led(int argc, char *argv[])
{
	int fd;
	ralink_gpio_led_info led;

	led.gpio = atoi(argv[2]);
	if (led.gpio < 0 || led.gpio >= RALINK_GPIO_NUMBER) {
		printf("gpio number %d out of range (should be 0 ~ %d)\n", led.gpio, RALINK_GPIO_NUMBER);
		return;
	}
	led.on = (unsigned int)atoi(argv[3]);
	if (led.on > RALINK_GPIO_LED_INFINITY) {
		printf("on interval %d out of range (should be 0 ~ %d)\n", led.on, RALINK_GPIO_LED_INFINITY);
		return;
	}
	led.off = (unsigned int)atoi(argv[4]);
	if (led.off > RALINK_GPIO_LED_INFINITY) {
		printf("off interval %d out of range (should be 0 ~ %d)\n", led.off, RALINK_GPIO_LED_INFINITY);
		return;
	}
	led.blinks = (unsigned int)atoi(argv[5]);
	if (led.blinks > RALINK_GPIO_LED_INFINITY) {
		printf("number of blinking cycles %d out of range (should be 0 ~ %d)\n", led.blinks, RALINK_GPIO_LED_INFINITY);
		return;
	}
	led.rests = (unsigned int)atoi(argv[6]);
	if (led.rests > RALINK_GPIO_LED_INFINITY) {
		printf("number of resting cycles %d out of range (should be 0 ~ %d)\n", led.rests, RALINK_GPIO_LED_INFINITY);
		return;
	}
	led.times = (unsigned int)atoi(argv[7]);
	if (led.times > RALINK_GPIO_LED_INFINITY) {
		printf("times of blinking %d out of range (should be 0 ~ %d)\n", led.times, RALINK_GPIO_LED_INFINITY);
		return;
	}

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return;
	}
	if (ioctl(fd, RALINK_GPIO_LED_SET, &led) < 0) {
		perror("ioctl");
		close(fd);
		return;
	}
	close(fd);
}

void usage(char *cmd)
{
	printf("Usage: %s w - writing test (output)\n", cmd);
	printf("       %s r - reading test (input)\n", cmd);
	printf("       %s i (<gpio>) - interrupt test for gpio number\n", cmd);
	printf("       %s l <gpio> <on> <off> <blinks> <rests> <times>\n", cmd);
	printf("            - set led on <gpio>(0~24) on/off interval, no. of blinking/resting cycles, times of blinking\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(argv[0]);

	switch (argv[1][0]) {
	case 'w':
		gpio_test_write();
		break;
	case 'r':
		gpio_test_read();
		break;
	case 'i':
		if (argc == 3)
			gpio_test_intr(atoi(argv[2]));
		else
			gpio_test_intr(0);
		break;
	case 'l':
		if (argc != 8)
			usage(argv[0]);
		gpio_set_led(argc, argv);
		break;
	default:
		usage(argv[0]);
	}

	return 0;
}

