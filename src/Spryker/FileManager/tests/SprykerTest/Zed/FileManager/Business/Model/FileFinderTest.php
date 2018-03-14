<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\FileManager\Business\Model;

use Codeception\Test\Unit;
use Orm\Zed\FileManager\Persistence\SpyFile;
use Orm\Zed\FileManager\Persistence\SpyFileInfo;
use Orm\Zed\FileManager\Persistence\SpyFileInfoQuery;
use Orm\Zed\FileManager\Persistence\SpyFileQuery;
use Spryker\Zed\FileManager\Business\Model\FileFinder;
use Spryker\Zed\FileManager\Persistence\FileManagerQueryContainerInterface;

class FileFinderTest extends Unit
{
    /**
     * @return \Spryker\Zed\FileManager\Persistence\FileManagerQueryContainerInterface
     */
    protected function getQueryContainer()
    {
        return $this->getMockBuilder(FileManagerQueryContainerInterface::class)->getMock();
    }

    /**
     * @return \Orm\Zed\FileManager\Persistence\SpyFileQuery
     */
    protected function getSpyFileQueryMock()
    {
        return $this->getMockBuilder(SpyFileQuery::class)->getMock();
    }

    /**
     * @return \Orm\Zed\FileManager\Persistence\SpyFileQuery
     */
    protected function getSpyFileInfoQueryMock()
    {
        return $this->getMockBuilder(SpyFileInfoQuery::class)->getMock();
    }

    /**
     * @return \Orm\Zed\FileManager\Persistence\SpyFile
     */
    protected function getMockedFile()
    {
        $file = new SpyFile();
        $file->setFileName('test.txt');
        $file->setIdFile(1);

        return $file;
    }

    /**
     * @return \Orm\Zed\FileManager\Persistence\SpyFileInfo
     */
    protected function getMockedFileInfo()
    {
        $fileInfo = new SpyFileInfo();
        $fileInfo->setFileExtension('txt');
        $fileInfo->setVersionName('v. 1');
        $fileInfo->setSize(1024);
        $fileInfo->setStorageFileName('report.txt');

        return $fileInfo;
    }

    /**
     * @return void
     */
    public function testGetFile()
    {
        $queryContainerMock = $this->getQueryContainer();
        $spyFileQueryMock = $this->getSpyFileQueryMock();

        $spyFileQueryMock->expects($this->once())
            ->method('findOne')
            ->willReturn($this->getMockedFile());

        $queryContainerMock->expects($this->once())
            ->method('queryFileById')
            ->willReturn($spyFileQueryMock);

        $fileFinder = new FileFinder($queryContainerMock);
        $file = $fileFinder->getFile(1);
        $this->assertEquals('test.txt', $file->getFileName());
        $this->assertEquals(1, $file->getIdFile());
    }

    /**
     * @return void
     */
    public function testGetLatestFileInfoByFkFile()
    {
        $queryContainerMock = $this->getQueryContainer();
        $spyFileInfoQueryMock = $this->getSpyFileInfoQueryMock();

        $spyFileInfoQueryMock->expects($this->once())
            ->method('findOne')
            ->willReturn($this->getMockedFileInfo());

        $queryContainerMock->expects($this->once())
            ->method('queryFileInfoByFkFile')
            ->willReturn($spyFileInfoQueryMock);

        $fileFinder = new FileFinder($queryContainerMock);
        $fileInfo = $fileFinder->getLatestFileInfoByFkFile(1);
        $this->assertEquals('txt', $fileInfo->getFileExtension());
        $this->assertEquals('v. 1', $fileInfo->getVersionName());
        $this->assertEquals(1024, $fileInfo->getSize());
        $this->assertEquals('report.txt', $fileInfo->getStorageFileName());
    }

    /**
     * @return void
     */
    public function testGetFileInfo()
    {
        $queryContainerMock = $this->getQueryContainer();
        $spyFileInfoQueryMock = $this->getSpyFileInfoQueryMock();

        $spyFileInfoQueryMock->expects($this->once())
            ->method('findOne')
            ->willReturn($this->getMockedFileInfo());

        $queryContainerMock->expects($this->once())
            ->method('queryFileInfo')
            ->willReturn($spyFileInfoQueryMock);

        $fileFinder = new FileFinder($queryContainerMock);
        $fileInfo = $fileFinder->getFileInfo(1);
        $this->assertEquals('txt', $fileInfo->getFileExtension());
        $this->assertEquals('v. 1', $fileInfo->getVersionName());
        $this->assertEquals(1024, $fileInfo->getSize());
        $this->assertEquals('report.txt', $fileInfo->getStorageFileName());
    }
}
