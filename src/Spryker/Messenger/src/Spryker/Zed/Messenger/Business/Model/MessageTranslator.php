<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Messenger\Business\Model;

use Symfony\Component\Translation\TranslatorInterface;

class MessageTranslator implements MessageTranslatorInterface
{
    /**
     * @var \Symfony\Component\Translation\TranslatorInterface
     */
    protected $symfonyTranslator;

    /**
     * @var \Spryker\Zed\MessengerExtension\Dependency\Plugin\TranslationPluginInterface[]
     */
    protected $translationPlugins;

    /**
     * @param \Symfony\Component\Translation\TranslatorInterface $symfonyTranslator
     * @param \Spryker\Zed\MessengerExtension\Dependency\Plugin\TranslationPluginInterface[] $translationPlugins
     */
    public function __construct(TranslatorInterface $symfonyTranslator, array $translationPlugins)
    {
        $this->symfonyTranslator = $symfonyTranslator;
        $this->translationPlugins = $translationPlugins;
    }

    /**
     * @param string $keyName
     * @param array $data
     *
     * @return string
     */
    public function translate(string $keyName, array $data = []): string
    {
        foreach ($this->translationPlugins as $translationPlugin) {
            if ($translationPlugin->hasKey($keyName)) {
                return $translationPlugin->translate($keyName, $data);
            }
        }

        return $this->symfonyTranslator->trans($keyName, $data);
    }
}
