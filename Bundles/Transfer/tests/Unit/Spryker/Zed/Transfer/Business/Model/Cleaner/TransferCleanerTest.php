<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Unit\Spryker\Zed\Transfer\Business\Model\Cleaner;

use PHPUnit_Framework_TestCase;
use Spryker\Zed\Transfer\Business\Model\TransferCleaner;

/**
 * @deprecated
 *
 * @group Unit
 * @group Spryker
 * @group Zed
 * @group Transfer
 * @group Business
 * @group Model
 * @group Cleaner
 * @group TransferCleanerTest
 */
class TransferCleanerTest extends PHPUnit_Framework_TestCase
{

    const TEST_FILE_NAME = 'TestTransfer.php';

    /**
     * @return void
     */
    public function setUp()
    {
        $testDirectory = $this->getTestDirectory();
        if (!is_dir($testDirectory)) {
            mkdir($testDirectory, 0775, true);
        }

        file_put_contents($testDirectory . static::TEST_FILE_NAME, '');
    }

    /**
     * @return string
     */
    private function getTestDirectory()
    {
        return __DIR__ . '/Fixtures/';
    }

    /**
     * @return void
     */
    public function tearDown()
    {
        $testFile1 = $this->getTestDirectory() . static::TEST_FILE_NAME;
        if (file_exists($testFile1)) {
            unlink($testFile1);
        }

        if (is_dir($this->getTestDirectory())) {
            rmdir($this->getTestDirectory());
        }
    }

    /**
     * @return void
     */
    public function testExecuteShouldDeleteAllFilesInADirectory()
    {
        $this->assertTrue(file_exists($this->getTestDirectory() . static::TEST_FILE_NAME));

        $cleaner = new TransferCleaner($this->getTestDirectory());
        $cleaner->cleanDirectory();

        $this->assertFalse(file_exists($this->getTestDirectory() . static::TEST_FILE_NAME));
    }

}
