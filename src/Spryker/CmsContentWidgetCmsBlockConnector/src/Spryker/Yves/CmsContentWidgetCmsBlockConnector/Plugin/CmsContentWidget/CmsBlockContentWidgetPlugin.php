<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\CmsContentWidgetCmsBlockConnector\Plugin\CmsContentWidget;

use ArrayObject;
use DateTime;
use Generated\Shared\Transfer\SpyCmsBlockEntityTransfer;
use Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface;
use Spryker\Yves\CmsContentWidget\Dependency\CmsContentWidgetPluginInterface;
use Spryker\Yves\Kernel\AbstractPlugin;
use Twig_Environment;

/**
 * @method \Spryker\Yves\CmsContentWidgetCmsBlockConnector\CmsContentWidgetCmsBlockConnectorFactory getFactory()
 */
class CmsBlockContentWidgetPlugin extends AbstractPlugin implements CmsContentWidgetPluginInterface
{
    /**
     * @var \Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface
     */
    protected $widgetConfiguration;

    /**
     * @var string
     */
    protected $localeName;

    /**
     * @var string
     */
    protected $storeName;

    /**
     * @param \Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface $widgetConfiguration
     */
    public function __construct(CmsContentWidgetConfigurationProviderInterface $widgetConfiguration)
    {
        $this->widgetConfiguration = $widgetConfiguration;
        $this->localeName = $this->getLocale();
        $this->storeName = $this->getApplication()['store'];
    }

    /**
     * @return callable
     */
    public function getContentWidgetFunction()
    {
        return [$this, 'contentWidgetFunction'];
    }

    /**
     * @param \Twig_Environment $twig
     * @param array $context
     * @param array $blockNames
     * @param string|null $templateIdentifier
     *
     * @return string
     */
    public function contentWidgetFunction(Twig_Environment $twig, array $context, array $blockNames = [], $templateIdentifier = null): string
    {
        $blocks = $this->getBlockDataByNames($blockNames);
        $templatePath = $this->resolveTemplatePath($templateIdentifier);
        $rendered = '';

        foreach ($blocks as $block) {
            $blockData = $this->getCmsBlockTransfer($block);

            $isActive = $this->validateBlock($blockData);
            $isActive &= $this->validateDates($blockData);

            if ($isActive) {
                $rendered .= $twig->render($templatePath, [
                    'placeholders' => $this->getPlaceholders($blockData->getSpyCmsBlockGlossaryKeyMappings()),
                    'cmsContent' => $blockData,
                ]);
            }
        }

        return $rendered;
    }

    /**
     * @param string|null $templateIdentifier
     *
     * @return string
     */
    protected function resolveTemplatePath($templateIdentifier = null): string
    {
        if (!$templateIdentifier) {
            $templateIdentifier = CmsContentWidgetConfigurationProviderInterface::DEFAULT_TEMPLATE_IDENTIFIER;
        }

        return $this->widgetConfiguration->getAvailableTemplates()[$templateIdentifier];
    }

    /**
     * @param array $blockNames
     *
     * @return array
     */
    protected function getBlockDataByNames(array &$blockNames): array
    {
        $blocks = $this->getFactory()
            ->getCmsBlockStorageClient()
            ->findBlocksByNames($blockNames, $this->localeName, $this->storeName);

        return $blocks;
    }

    /**
     * @param \Generated\Shared\Transfer\SpyCmsBlockEntityTransfer $cmsBlockData
     *
     * @return bool
     */
    protected function validateBlock(SpyCmsBlockEntityTransfer $cmsBlockData): bool
    {
        return $cmsBlockData->getCmsBlockTemplate() !== null;
    }

    /**
     * @param \Generated\Shared\Transfer\SpyCmsBlockEntityTransfer $spyCmsBlockTransfer
     *
     * @return bool
     */
    protected function validateDates(SpyCmsBlockEntityTransfer $spyCmsBlockTransfer): bool
    {
        $dateToCompare = new DateTime();

        if ($spyCmsBlockTransfer->getValidFrom() !== null) {
            $validFrom = new DateTime($spyCmsBlockTransfer->getValidFrom());

            if ($dateToCompare < $validFrom) {
                return false;
            }
        }

        if ($spyCmsBlockTransfer->getValidTo() !== null) {
            $validTo = new DateTime($spyCmsBlockTransfer->getValidTo());

            if ($dateToCompare > $validTo) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param \ArrayObject $mappings
     *
     * @return array
     */
    protected function getPlaceholders(ArrayObject $mappings): array
    {
        $placeholders = [];
        foreach ($mappings as $mapping) {
            $placeholders[$mapping->getPlaceholder()] = $mapping->getGlossaryKey()->getKey();
        }

        return $placeholders;
    }

    /**
     * @param array $data
     *
     * @return \Generated\Shared\Transfer\SpyCmsBlockEntityTransfer
     */
    protected function getCmsBlockTransfer(array $data): SpyCmsBlockEntityTransfer
    {
        return (new SpyCmsBlockEntityTransfer())->fromArray($data, true);
    }
}
