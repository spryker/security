<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Transfer\Business\Model\Generator;

class DefinitionNormalizer implements DefinitionNormalizerInterface
{
    public const KEY_BUNDLE = 'bundle';
    public const KEY_CONTAINING_BUNDLE = 'containing bundle';
    public const KEY_NAME = 'name';
    public const KEY_PROPERTY = 'property';
    public const KEY_BUNDLES = 'bundles';
    public const KEY_DEPRECATED = 'deprecated';

    /**
     * @param array $transferDefinitions
     *
     * @return array
     */
    public function normalizeDefinitions(array $transferDefinitions)
    {
        $normalizedDefinitions = [];
        foreach ($transferDefinitions as $transferDefinition) {
            $normalizedDefinition = [
                self::KEY_BUNDLE => $transferDefinition[self::KEY_BUNDLE],
                self::KEY_CONTAINING_BUNDLE => $transferDefinition[self::KEY_CONTAINING_BUNDLE],
                self::KEY_NAME => $transferDefinition[self::KEY_NAME],
                self::KEY_DEPRECATED => isset($transferDefinition[self::KEY_DEPRECATED]) ? $transferDefinition[self::KEY_DEPRECATED] : null,
                self::KEY_PROPERTY => $this->normalizeAttributes($transferDefinition[self::KEY_PROPERTY] ?? [], $transferDefinition[self::KEY_BUNDLE]),
            ];

            $normalizedDefinitions[] = $normalizedDefinition;
        }

        return $normalizedDefinitions;
    }

    /**
     * @param array $attributes
     * @param string $bundle
     *
     * @return array
     */
    protected function normalizeAttributes(array $attributes, $bundle)
    {
        if ($attributes === []) {
            return [];
        }

        if (isset($attributes[0])) {
            return $this->addBundleToAttributes($attributes, $bundle);
        }

        return $this->addBundleToAttributes([$attributes], $bundle);
    }

    /**
     * @param array $attributes
     * @param string $bundle
     *
     * @return array
     */
    protected function addBundleToAttributes(array $attributes, $bundle)
    {
        foreach ($attributes as &$attribute) {
            $attribute[self::KEY_BUNDLES] = [$bundle];
        }

        return $attributes;
    }
}
