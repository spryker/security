<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\UtilDateTime\Model;

interface DateTimeFormatterInterface
{
    /**
     * @param string $dateTime
     *
     * @return string
     */
    public function formatDate($dateTime);

    /**
     * @param string $dateTime
     *
     * @return string
     */
    public function formatTime($dateTime);

    /**
     * @param string $dateTime
     *
     * @return string
     */
    public function formatDateTime($dateTime);
}
