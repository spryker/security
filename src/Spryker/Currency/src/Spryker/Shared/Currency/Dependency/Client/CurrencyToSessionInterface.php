<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Currency\Dependency\Client;

interface CurrencyToSessionInterface
{

    /**
     * @param string $name
     * @param mixed $value
     *
     * @return void
     */
    public function set($name, $value);

    /**
     * @param string $name The attribute name
     * @param mixed|null $default The default value if not found
     *
     * @return mixed
     */
    public function get($name, $default = null);

}
