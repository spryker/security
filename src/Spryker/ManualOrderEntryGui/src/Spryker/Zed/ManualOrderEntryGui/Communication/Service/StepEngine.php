<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ManualOrderEntryGui\Communication\Service;

use Symfony\Component\HttpFoundation\Request;

class StepEngine
{
    /**
     * @var string
     */
    protected $nextStepName;

    /**
     * @param string $nextStepName
     */
    public function __construct($nextStepName)
    {
        $this->nextStepName = $nextStepName;
    }

    /**
     * @param \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\ManualOrderEntryFormPluginInterface[] $formPlugins
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return array
     */
    public function filterFormPlugins($formPlugins, Request $request, $quoteTransfer)
    {
        $filteredPlugins = [];

        foreach ($formPlugins as $formPlugin) {
            if ($request->request->get($this->nextStepName) !== null) {
                $filteredPlugins[] = $formPlugin;
            }

            if (!$this->isFormSubmitted($formPlugin, $request)) {
                break;
            }

            if ($request->request->get($this->nextStepName) === null) {
                $filteredPlugins[] = $formPlugin;
            }
        }

        $filteredPlugins = $this->augmentFilteredPlugins($formPlugins, $filteredPlugins);

        return $filteredPlugins;
    }

    /**
     * @param \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\ManualOrderEntryFormPluginInterface $formPlugin
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return bool
     */
    protected function isFormSubmitted($formPlugin, $request)
    {
        return ($request->request->get($formPlugin->getName()) !== null);
    }
    
    /**
     * @param \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\ManualOrderEntryFormPluginInterface[] $formPlugins
     * @param \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\ManualOrderEntryFormPluginInterface[] $filteredPlugins
     *
     * @return \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\ManualOrderEntryFormPluginInterface[]
     */
    protected function augmentFilteredPlugins($formPlugins, $filteredPlugins): array
    {
        if (count($formPlugins) && !count($filteredPlugins)) {
            $filteredPlugins[] = array_shift($formPlugins);
        }

        return $filteredPlugins;
    }
}
