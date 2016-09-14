<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Application\Module;

use Codeception\Module;
use Symfony\Component\Process\Process;

class Infrastructure extends Module
{
    const TEST_ENV_SCRIPT = 'setup_test.sh';

    /**
     * @return $this
     */
    public function runCollectors()
    {
        $this->runTestSetup('--collectors');

        return $this;
    }

    /**
     * @param string $argument
     *
     * @return \Symfony\Component\Process\Process
     */
    protected function runTestSetup($argument)
    {
        $process = new Process(sprintf(
            '%s' . self::TEST_ENV_SCRIPT . ' %s',
            APPLICATION_ROOT_DIR,
            $argument
        ));

        $process->run();

        return $process;
    }
}
