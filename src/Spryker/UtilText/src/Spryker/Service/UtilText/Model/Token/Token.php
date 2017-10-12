<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\UtilText\Model\Token;

class Token implements TokenInterface
{
    /**
     * @param string $rawToken
     * @param array $options
     *
     * @return string
     */
    public function generate($rawToken, array $options = [])
    {
        return base64_encode(password_hash($rawToken, PASSWORD_DEFAULT, $options));
    }

    /**
     * @param string $rawToken
     * @param string $hash
     *
     * @return bool
     */
    public function check($rawToken, $hash)
    {
        return password_verify($rawToken, base64_decode($hash));
    }
}
