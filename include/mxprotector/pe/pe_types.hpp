/**
 * @file pe_types.hpp
 * @brief [BUILDER] Aggregate header — re-exports PE format types.
 *
 * @details The PE format types used to live in this single file.
 *          They are now split by responsibility under
 *          `mxprotector/pe/types/`:
 *
 *            - `constants.hpp`       — signatures, flags, characteristics.
 *            - `headers.hpp`         — DOS / file / optional / NT / section.
 *            - `imports.hpp`         — import descriptors and views.
 *            - `exports.hpp`         — export directory and views.
 *            - `relocations.hpp`     — base relocation block and views.
 *            - `tls.hpp`             — TLS directory.
 *            - `resources.hpp`       — resource directory tree.
 *            - `delay_imports.hpp`   — delay-load descriptor.
 *            - `debug.hpp`           — debug directory.
 *            - `section_info.hpp`    — high-level `SectionInfo`.
 *
 *          Existing code that includes this aggregate keeps working
 *          unchanged. New code is encouraged to include only the
 *          piece it needs.
 */

#pragma once

#include "mxprotector/pe/types/constants.hpp"
#include "mxprotector/pe/types/headers.hpp"
#include "mxprotector/pe/types/imports.hpp"
#include "mxprotector/pe/types/exports.hpp"
#include "mxprotector/pe/types/relocations.hpp"
#include "mxprotector/pe/types/tls.hpp"
#include "mxprotector/pe/types/resources.hpp"
#include "mxprotector/pe/types/delay_imports.hpp"
#include "mxprotector/pe/types/debug.hpp"
#include "mxprotector/pe/types/section_info.hpp"
