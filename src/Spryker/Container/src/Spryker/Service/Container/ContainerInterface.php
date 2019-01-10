<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\Container;

use Psr\Container\ContainerInterface as PsrContainerInterface;

interface ContainerInterface extends PsrContainerInterface
{
    /**
     * @param string $id
     * @param callable|string $service
     *
     * @return void
     */
    public function set(string $id, $service): void;

    /**
     * This one can be used to extend an existing Service without loading it.
     *
     * @param string $id
     * @param callable $service
     *
     * @return callable
     */
    public function extend(string $id, $service): callable;

    /**
     * Removes an entry from the container.
     *
     * @param string $id
     *
     * @return void
     */
    public function remove(string $id): void;
}
