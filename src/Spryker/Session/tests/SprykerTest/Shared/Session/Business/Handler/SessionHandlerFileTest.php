<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Shared\Session\Business\Handler;

use Codeception\Test\Unit;
use Spryker\Shared\NewRelicApi\NewRelicApi;
use Spryker\Shared\Session\Business\Handler\SessionHandlerFile;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Shared
 * @group Session
 * @group Business
 * @group Handler
 * @group SessionHandlerFileTest
 * Add your own group annotations below this line
 */
class SessionHandlerFileTest extends Unit
{
    const LIFETIME = 20;

    const SESSION_NAME = 'sessionName';

    const SESSION_ID = 'sessionId';
    const SESSION_ID_2 = 'anotherSessionId';

    const SESSION_DATA = 'sessionData';

    /**
     * @return void
     */
    public function tearDown()
    {
        if (is_dir($this->getFixtureDirectory())) {
            $filesystem = new Filesystem();
            $filesystem->remove($this->getFixtureDirectory());
        }
    }

    /**
     * @return string
     */
    private function getFixtureDirectory()
    {
        return __DIR__ . DIRECTORY_SEPARATOR . 'Fixtures';
    }

    /**
     * @return string
     */
    protected function getSavePath()
    {
        return $this->getFixtureDirectory() . DIRECTORY_SEPARATOR . 'Sessions';
    }

    /**
     * @return void
     */
    public function testCallOpenMustCreateDirectoryIfNotExists()
    {
        $this->assertFalse(is_dir($this->getSavePath()));

        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $sessionHandlerFile->open($this->getSavePath(), self::SESSION_NAME);

        $this->assertTrue(is_dir($this->getSavePath()));
    }

    /**
     * @return void
     */
    public function testCallOpenMustReturnTrue()
    {
        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $result = $sessionHandlerFile->open($this->getSavePath(), self::SESSION_NAME);

        $this->assertTrue($result);
    }

    /**
     * @return void
     */
    public function testCallCloseMustReturnTrue()
    {
        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $result = $sessionHandlerFile->close();

        $this->assertTrue($result);
    }

    /**
     * @return void
     */
    public function testCallWriteMustReturnFalseIfNoDataPassed()
    {
        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $sessionHandlerFile->open($this->getSavePath(), self::SESSION_NAME);
        $result = $sessionHandlerFile->write(self::SESSION_ID, '');

        $this->assertFalse($result);
    }

    /**
     * @return void
     */
    public function testCallWriteMustReturnTrueWhenDataCanBeWrittenToFile()
    {
        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $sessionHandlerFile->open($this->getSavePath(), self::SESSION_NAME);
        $result = $sessionHandlerFile->write(self::SESSION_ID, self::SESSION_DATA);

        $this->assertTrue($result);
    }

    /**
     * @return void
     */
    public function testWriteMustAllowZeroValue()
    {
        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $sessionHandlerFile->open($this->getSavePath(), self::SESSION_NAME);
        $result = $sessionHandlerFile->write(self::SESSION_ID, '0');

        $this->assertTrue($result);
    }

    /**
     * @return void
     */
    public function testCallReadMustReturnContentOfSessionForGivenSessionId()
    {
        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $sessionHandlerFile->open($this->getSavePath(), self::SESSION_NAME);
        $sessionHandlerFile->write(self::SESSION_ID, self::SESSION_DATA);

        $result = $sessionHandlerFile->read(self::SESSION_ID);

        $this->assertSame(self::SESSION_DATA, $result);
    }

    /**
     * @return void
     */
    public function testCallDestroyMustReturnTrueIfNoFileExistsForSessionId()
    {
        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $sessionHandlerFile->open($this->getSavePath(), self::SESSION_NAME);

        $result = $sessionHandlerFile->destroy(self::SESSION_ID);

        $this->assertTrue($result);
    }

    /**
     * @return void
     */
    public function testCallDestroyMustReturnTrueIfFileExistsForSessionId()
    {
        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $sessionHandlerFile->open($this->getSavePath(), self::SESSION_NAME);
        $sessionHandlerFile->write(self::SESSION_ID, self::SESSION_DATA);

        $result = $sessionHandlerFile->destroy(self::SESSION_ID);

        $this->assertTrue($result);
    }

    /**
     * @return void
     */
    public function testCallGcMustDeleteFilesWhichAreOlderThenMaxLifetime()
    {
        $sessionHandlerFile = new SessionHandlerFile($this->getSavePath(), self::LIFETIME, $this->createNewRelicApiMock());
        $sessionHandlerFile->open($this->getSavePath(), self::SESSION_NAME);
        $sessionHandlerFile->write(self::SESSION_ID, self::SESSION_DATA);
        $this->makeFileOlderThanItIs();
        $sessionHandlerFile->write(self::SESSION_ID_2, self::SESSION_DATA);
        $this->makeFileNewerThanItIs();

        $finder = new Finder();
        $finder->in($this->getSavePath());

        $this->assertCount(2, $finder);

        $sessionHandlerFile->gc(1);
        $this->assertCount(1, $finder);

        unlink($this->getSavePath() . '/session:' . self::SESSION_ID_2);
        rmdir($this->getSavePath());
    }

    /**
     * @return void
     */
    protected function makeFileOlderThanItIs()
    {
        touch($this->getSavePath() . DIRECTORY_SEPARATOR . 'session:' . self::SESSION_ID, time() - 200);
    }

    /**
     * @return void
     */
    protected function makeFileNewerThanItIs()
    {
        touch($this->getSavePath() . DIRECTORY_SEPARATOR . 'session:' . self::SESSION_ID_2, time() + 200);
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Shared\NewRelicApi\NewRelicApiInterface
     */
    protected function createNewRelicApiMock()
    {
        $mock = $this->getMockBuilder(NewRelicApi::class)
            ->disableOriginalConstructor()
            ->getMock();

        return $mock;
    }
}
