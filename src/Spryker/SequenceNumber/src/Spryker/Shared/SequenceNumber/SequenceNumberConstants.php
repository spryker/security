<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\SequenceNumber;

interface SequenceNumberConstants
{
    const ENVIRONMENT_PREFIX = 'environmentPrefix';

    /**
     * Specification:
     * - A list of limits per sequence name
     * - If limit is not set, the sequence is unlimited
     *
     * @example
     * [
     *  'SEQUENCE1' => 100,
     *  'SEQUENCE2' => 200,
     * ]
     */
    const LIMIT_LIST = 'SEQUENCE_NUMBER:LIMIT_LIST';
}
