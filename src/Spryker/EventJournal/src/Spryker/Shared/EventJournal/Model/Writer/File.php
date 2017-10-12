<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\EventJournal\Model\Writer;

use Spryker\Shared\Config\Config;
use Spryker\Shared\EventJournal\EventJournalConstants;
use Spryker\Shared\EventJournal\Model\EventInterface;

/**
 * @deprecated Use Log bundle instead
 */
class File extends AbstractWriter
{
    /**
     * @var resource[]
     */
    public static $fileHandles = [];

    /**
     * @var resource
     */
    public static $preferredHandle;

    /**
     * @inheritdoc
     */
    public function write(EventInterface $event)
    {
        $output = $this->getJsonEntry($event);
        if ($output === '') {
            return false;
        }

        return $this->optimisticRandomWrite($output);
    }

    /**
     * @param \Spryker\Shared\EventJournal\Model\EventInterface $event
     *
     * @return string
     */
    protected function getJsonEntry(EventInterface $event)
    {
        $json = json_encode($event->getFields());
        if ($json === false) {
            return '';
        }

        return $json . "\n";
    }

    /**
     * @param string $content
     *
     * @return bool
     */
    protected function optimisticRandomWrite($content)
    {
        for ($i = 0; $i <= 9; $i++) {
            $handle = $this->getOrCreateRandomFileHandle();
            $config = Config::get(EventJournalConstants::LOCK_OPTIONS);
            if (!empty($config[EventJournalConstants::NO_LOCK])) {
                self::$preferredHandle = $handle;
                fwrite($handle, $content);

                return true;
            }

            if ($this->acquireNonBlockingLock($handle)) {
                self::$preferredHandle = $handle;
                fwrite($handle, $content);
                $this->unlock($handle);

                return true;
            }
            self::$preferredHandle = null;
        }

        return false;
    }

    /**
     * @return resource
     */
    protected function getOrCreateRandomFileHandle()
    {
        if (self::$preferredHandle !== null) {
            return self::$preferredHandle;
        }
        $fileName = $this->getRandomFileName();
        if (!isset(static::$fileHandles[$fileName])) {
            $fileHandle = fopen($fileName, 'a');
            static::$fileHandles[$fileName] = $fileHandle;
        }

        return static::$fileHandles[$fileName];
    }

    /**
     * @return string
     */
    protected function getRandomFileName()
    {
        $path = $this->getLogPath();
        $path .= sprintf(
            '%s.%s.%d.log',
            'events',
            date('Y-m-d'),
            $this->getRandomizedFileIndex()
        );

        return $path;
    }

    /**
     * @return string
     */
    protected function getLogPath()
    {
        if (!isset($this->options[EventJournalConstants::OPTION_LOG_PATH])) {
            return APPLICATION_ROOT_DIR . '/data/common/event_journal';
        }

        return $this->options[EventJournalConstants::OPTION_LOG_PATH];
    }

    /**
     * @return int
     */
    protected function getRandomizedFileIndex()
    {
        return rand(0, 9);
    }

    /**
     * @param resource $handle
     *
     * @return bool
     */
    protected function acquireNonBlockingLock($handle)
    {
        return flock($handle, LOCK_EX | LOCK_NB);
    }

    /**
     * @param resource $handle
     *
     * @return void
     */
    protected function unlock($handle)
    {
        flock($handle, LOCK_UN);
    }
}
