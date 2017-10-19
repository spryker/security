<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSearch\Communication\Form;

use Spryker\Zed\ProductSearch\Persistence\ProductSearchQueryContainerInterface;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\Constraints\Callback;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Regex;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

abstract class AbstractAttributeKeyForm extends AbstractType
{
    const FIELD_KEY = 'key';

    const OPTION_FILTER_TYPE_CHOICES = 'filter_type_choices';
    const OPTION_IS_UPDATE = 'is_update';
    const OPTION_ATTRIBUTE_TRANSLATION_COLLECTION_OPTIONS = 'attribute_translation_collection_options';

    const GROUP_UNIQUE_KEY = 'unique_key_group';

    /**
     * @var \Spryker\Zed\ProductSearch\Persistence\ProductSearchQueryContainerInterface
     */
    protected $productSearchQueryContainer;

    /**
     * @param \Spryker\Zed\ProductSearch\Persistence\ProductSearchQueryContainerInterface $productSearchQueryContainer
     */
    public function __construct(ProductSearchQueryContainerInterface $productSearchQueryContainer)
    {
        $this->productSearchQueryContainer = $productSearchQueryContainer;
    }

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults([
            self::OPTION_IS_UPDATE => false,
            self::OPTION_ATTRIBUTE_TRANSLATION_COLLECTION_OPTIONS => [],
            'required' => false,
            'validation_groups' => function (FormInterface $form) {
                $groups = [Constraint::DEFAULT_GROUP];
                $originalData = $form->getConfig()->getData();
                $submittedData = $form->getData();

                if (!isset($originalData[self::FIELD_KEY]) || $submittedData[self::FIELD_KEY] !== $originalData[self::FIELD_KEY]) {
                    $groups[] = self::GROUP_UNIQUE_KEY;
                }

                return $groups;
            },
        ]);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return $this
     */
    abstract protected function addKeyField(FormBuilderInterface $builder, array $options);

    /**
     * @param string $key
     *
     * @return bool
     */
    abstract protected function isUniqueKey($key);

    /**
     * @return \Symfony\Component\Validator\Constraint[]
     */
    protected function createAttributeKeyFieldConstraints()
    {
        return [
            new NotBlank(),
            new Regex([
                'pattern' => '/^[a-z\-0-9_:]+$/',
                'message' => 'This field contains illegal characters. It should contain only lower case letters, ' .
                    'digits, numbers, underscores ("_"), hyphens ("-") and colons (":").',
            ]),
            new Callback([
                'methods' => [
                    function ($key, ExecutionContextInterface $context) {
                        if (!$this->isUniqueKey($key)) {
                            $context->addViolation('Attribute key is already used');
                        }
                    },
                ],
                'groups' => [self::GROUP_UNIQUE_KEY],
            ]),
        ];
    }
}
