/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Zhi Guan <guan@pku.edu.cn>                                  |
   +----------------------------------------------------------------------+
*/

#ifndef PHP_GMSSL_H
#define PHP_GMSSL_H

extern zend_module_entry gmssl_module_entry;
#define phpext_gmssl_ptr &gmssl_module_entry

#define PHP_GMSSL_VERSION PHP_VERSION

#if defined(ZTS) && defined(COMPILE_DL_GMSSL)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif	/* PHP_GMSSL_H */
