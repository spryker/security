<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\FileManagerGui\Communication\Table;

use Spryker\Service\UtilText\Model\Url\Url;

class FileInfoEditTable extends FileInfoTable
{
    /**
     * @param array $item
     *
     * @return array
     */
    protected function buildLinks($item)
    {
        $buttons = [];

        $buttons[] = $this->generateViewButton(
            Url::generate('/file-manager-gui/download-file', [
                static::REQUEST_ID_FILE_INFO => $item[static::COL_ID_FILE_INFO],
            ]),
            'Download'
        );
        $buttons[] = $this->generateRemoveButton(
            Url::generate('/file-manager-gui/delete-file/file-info', [
                static::REQUEST_ID_FILE_INFO => $item[static::COL_ID_FILE_INFO],
                static::REQUEST_ID_FILE => $item[static::COL_FK_FILE],
            ]),
            'Delete'
        );

        return $buttons;
    }
}
