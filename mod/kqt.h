// Netlink family definition

#ifndef _KQT_H
#define _KQT_H

#define KQT_GENL_NAME "kqt"
#define KQT_GENL_VERSION 1

enum kqt_genl_cmd {
  KQT_GET_DEVICE,
  KQT_SET_DEVICE,
  __KQT_GENL_CMD_MAX,
};



#endif // _KQT_H
