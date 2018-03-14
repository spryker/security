<?php
/**
 * Created by PhpStorm.
 * User: dmitriikadykov
 * Date: 27.02.18
 * Time: 18:27
 */

namespace SprykerTest\Zed\FileManager\Business\Model;

use Codeception\Test\Unit;
use Orm\Zed\FileManager\Persistence\SpyFile;
use Orm\Zed\FileManager\Persistence\SpyFileInfo;
use Spryker\Zed\FileManager\Business\Model\FileFinderInterface;
use Spryker\Zed\FileManager\Business\Model\FileVersion;

class FileVersionTest  extends Unit
{

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
     * @return \Spryker\Zed\FileManager\Business\Model\FileFinderInterface
     */
    protected function createFileFinderMock()
    {
        return $this->getMockBuilder(FileFinderInterface::class)->getMock();
    }

    /**
     * @return \Orm\Zed\FileManager\Persistence\SpyFileInfo
     */
    protected function getMockedFileInfo()
    {
        $fileInfo = new SpyFileInfo();
        $fileInfo->setFileExtension('txt');
        $fileInfo->setVersionName('v. 1');
        $fileInfo->setVersion(1);
        $fileInfo->setSize(1024);
        $fileInfo->setStorageFileName('report.txt');
        $fileInfo->setFile($this->getMockedFile());

        return $fileInfo;
    }

    /**
     * @return void
     */
    public function testGetNewVersionNumber()
    {
        $fileFinderMock = $this->createFileFinderMock();

        $fileFinderMock->expects($this->once())
            ->method('getLatestFileInfoByFkFile')
            ->willReturn($this->getMockedFileInfo());

        $fileVersion = new FileVersion($fileFinderMock);

        $this->assertEquals(2, $fileVersion->getNewVersionNumber(1));
    }

    /**
     * @return void
     */
    public function testGetNewVersionName()
    {
        $fileFinderMock = $this->createFileFinderMock();
        $fileVersion = new FileVersion($fileFinderMock);

        $this->assertEquals('v. 2', $fileVersion->getNewVersionName(2));
    }

}
