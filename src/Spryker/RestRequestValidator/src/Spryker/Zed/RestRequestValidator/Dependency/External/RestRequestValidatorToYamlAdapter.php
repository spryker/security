<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\RestRequestValidator\Dependency\External;

use Symfony\Component\Yaml\Yaml;

class RestRequestValidatorToYamlAdapter implements RestRequestValidatorToYamlAdapterInterface
{
    /**
     * @param array $input
     * @param int $inline
     * @param int $indent
     * @param int $flags
     *
     * @return string
     */
    public function dump(array $input, int $inline = 2, int $indent = 4, int $flags = 0): string
    {
        return Yaml::dump($input, $inline, $indent, $flags);
    }

    /**
     * @param string $filename
     * @param int $flags
     *
     * @return array
     */
    public function parseFile(string $filename, int $flags = 0): array
    {
        return Yaml::parseFile($filename, $flags);
    }
}
