/**
 * @file qsv_config.h
 * @brief Build-time toggles for qsvault.
 *
 * CLOUD LAYER TOGGLE. Off by default. To enable it, see tools/vault/CLOUD_SETUP.md, then either
 * change the value below or pass /DQSV_CLOUD_ENABLED=1 to the compiler (build_vault.bat does this
 * when called with "cloud").
 */
#ifndef QSV_CONFIG_H
#define QSV_CONFIG_H

#ifndef QSV_CLOUD_ENABLED
#define QSV_CLOUD_ENABLED 0
#endif

#endif
